use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;
use libafl::prelude::{Named, Observer};
use libafl::{
    bolts::{current_nanos, current_time, rands::StdRand, tuples::tuple_list},
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{command::CommandExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, UsesInput},
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{calibrate::CalibrationStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libaflgo::halo::{
    HaloController, HaloInputObserver, HaloMetadataFeedback, HaloMutator, HaloShared,
};
use libaflgo::{CoolingSchedule, DistanceFeedback, DistanceObserver};
use serde::{Deserialize, Serialize};

static SHARED_PTR: AtomicUsize = AtomicUsize::new(0);

fn snapshot() -> (bool, Option<f64>) {
    let ptr = SHARED_PTR.load(Ordering::Relaxed) as *const u8;
    if ptr.is_null() {
        return (false, None);
    }
    let targets = unsafe { std::slice::from_raw_parts(ptr.add(MAP_SIZE + 16), TARGETS_SIZE) };
    let reached = targets.iter().any(|&v| v != 0);
    let sum = unsafe { (ptr.add(MAP_SIZE) as *const u64).read_volatile() };
    let count = unsafe { (ptr.add(MAP_SIZE + 8) as *const u64).read_volatile() };
    (
        reached,
        if count > 0 {
            Some(sum as f64 / (1000.0 * count as f64))
        } else {
            None
        },
    )
}
fn reset_input() {}

const MAP_SIZE: usize = 2_621_440;
const TARGETS_SIZE: usize = 256;
const SHARED_SIZE: usize = MAP_SIZE + 16 + TARGETS_SIZE + 8;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    target: PathBuf,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    logfile: PathBuf,
    #[arg(long)]
    halo_seed: Option<u64>,
    #[arg(long)]
    halo_only: bool,
    #[arg(long, default_value_t = 1200)]
    timeout: u64,
    #[arg(last = true, required = true)]
    target_args: Vec<String>,
}

struct SharedState {
    _file: File,
    ptr: *mut u8,
}

impl SharedState {
    fn new(path: &PathBuf) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(SHARED_SIZE as u64)?;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SHARED_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(Error::illegal_state("cannot map CLI observation state"));
        }
        Ok(Self {
            _file: file,
            ptr: ptr.cast(),
        })
    }
}

impl Drop for SharedState {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.cast(), SHARED_SIZE) };
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CliDistanceObserver {
    name: String,
    counters: usize,
    distance: f64,
}

impl Named for CliDistanceObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S: UsesInput> DistanceObserver<S> for CliDistanceObserver {
    fn distance(&self) -> f64 {
        self.distance
    }
}

impl<S: UsesInput> Observer<S> for CliDistanceObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        unsafe {
            (self.counters as *mut u64).write_volatile(0);
            (self.counters as *mut u64).add(1).write_volatile(0);
        }
        self.distance = f64::NAN;
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        let sum = unsafe { (self.counters as *mut u64).read_volatile() };
        let count = unsafe { (self.counters as *mut u64).add(1).read_volatile() };
        if count > 0 {
            self.distance = sum as f64 / (1_000.0 * count as f64);
        }
        Ok(())
    }
}

fn run(args: Args) -> Result<(), Error> {
    if !args.target.is_file() || !args.input.is_dir() {
        return Err(Error::illegal_argument(
            "target or seed directory is missing",
        ));
    }
    if args
        .target_args
        .iter()
        .filter(|arg| arg.as_str() == "@@")
        .count()
        != 1
    {
        return Err(Error::illegal_argument(
            "target arguments need exactly one @@",
        ));
    }
    fs::create_dir_all(&args.output)?;
    let target = args.target.canonicalize()?;
    let output = args.output.canonicalize()?;
    let shared_path = output.join(".halo_cli_state");
    let shared = SharedState::new(&shared_path)?;
    SHARED_PTR.store(shared.ptr as usize, Ordering::Relaxed);
    let halo: HaloShared = Arc::new(Mutex::new(HaloController::open(&output)?));
    let monitor_halo = halo.clone();
    let log = RefCell::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&args.logfile)?,
    );
    let monitor = SimpleMonitor::with_user_monitor(
        move |line| {
            println!("{line}");
            let guard = monitor_halo.lock().unwrap_or_else(|p| p.into_inner());
            let totals = &guard.engine.totals;
            let _ = writeln!(
                log.borrow_mut(),
                "{:?} {line} halo_observed={} halo_reached={} halo_generated={}",
                current_time(),
                totals.observed,
                totals.reached,
                totals.generated
            );
        },
        true,
    );
    let mut mgr = SimpleEventManager::new(monitor);

    let edges_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::<u8, false>::from_mut_ptr("edges", shared.ptr, MAP_SIZE)
    });
    let time_observer = TimeObserver::new("time");
    let distance_observer = CliDistanceObserver {
        name: "distance".to_string(),
        counters: unsafe { shared.ptr.add(MAP_SIZE) as usize },
        distance: f64::NAN,
    };
    let targets_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::<u8, false>::from_mut_ptr(
            "targets",
            shared.ptr.add(MAP_SIZE + 16),
            TARGETS_SIZE,
        )
    });
    let halo_observer = HaloInputObserver::new(halo.clone(), reset_input, snapshot);
    let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
    let targets_feedback = MaxMapFeedback::new(&targets_observer);
    let calibration = CalibrationStage::new(&map_feedback);
    let mut feedback = feedback_or!(
        HaloMetadataFeedback::new(halo.clone()),
        map_feedback,
        TimeFeedback::with_observer(&time_observer),
        DistanceFeedback::with_observer(
            &distance_observer,
            Some(CoolingSchedule::Exponential),
            Duration::from_secs(600),
        ),
        targets_feedback
    );
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(
        StdRand::with_seed(args.halo_seed.unwrap_or_else(current_nanos)),
        InMemoryOnDiskCorpus::<BytesInput>::new(output.join("queue"))?,
        OnDiskCorpus::new(output.join("crashes"))?,
        &mut feedback,
        &mut objective,
    )?;
    let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
        &mut state,
        &edges_observer,
        Some(PowerSchedule::FAST),
    ));
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut builder = CommandExecutor::builder();
    builder
        .program(target)
        // This pinned LibAFL CommandExecutor clones the command with env_clear().
        // Pass the monitor's MAGMA_STORAGE (and sanitizer settings) to every
        // target child, or Magma silently records no canary events.
        .envs(std::env::vars_os())
        .env("HALO_CLI_SHM", &shared_path)
        .timeout(Duration::from_millis(args.timeout));
    for arg in &args.target_args {
        if arg == "@@" {
            builder.arg_input_file(output.join(".current_input"));
        } else {
            builder.arg(arg);
        }
    }
    let mut executor = builder.build(tuple_list!(
        edges_observer,
        time_observer,
        distance_observer,
        targets_observer,
        halo_observer
    ))?;
    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[args.input])?;
    println!("Imported {} inputs", state.corpus().count());
    let halo_stage = StdMutationalStage::new(HaloMutator::new(halo.clone()));
    if args.halo_only {
        let mut stages = tuple_list!(calibration, halo_stage);
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    } else {
        let havoc = StdMutationalStage::new(StdScheduledMutator::new(havoc_mutations()));
        let mut stages = tuple_list!(calibration, halo_stage, havoc);
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    }
    halo.lock()
        .unwrap_or_else(|p| p.into_inner())
        .checkpoint()?;
    Ok(())
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("Halo CLI: {error}");
        std::process::exit(1);
    }
}
