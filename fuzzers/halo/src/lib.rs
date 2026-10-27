//! Halo's paper-based input generator on the LibAFLGo execution stack.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{
    cell::RefCell,
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::exit,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::{Parser, ValueEnum};
use libafl::{
    bolts::{
        current_nanos, current_time,
        os::dup2,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{calibrate::CalibrationStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer};
use libaflgo::{
    halo::{HaloController, HaloInputObserver, HaloMetadataFeedback, HaloMutator, HaloShared},
    CoolingSchedule, DistanceFeedback,
};
use libaflgo_targets::{
    beacon,
    distance::{self, InProcessDistanceObserver},
    target::{self, get_targets_map_observer},
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    output: PathBuf,
    #[arg(short, long)]
    input: PathBuf,
    #[arg(short, long, default_value = "halo.log")]
    logfile: PathBuf,
    #[arg(short, long, default_value_t = 1200)]
    timeout: u64,
    #[arg(short = 'D', long)]
    show_target_output: bool,
    #[arg(long)]
    halo_seed: Option<u64>,
    #[arg(long)]
    halo_only: bool,
    #[arg(short = 'z', long, default_value = "exp")]
    cooling_schedule: CoolingScheduleClap,
    #[arg(short = 'c', long, default_value_t = 10)]
    time_to_exploit: u64,
}

#[derive(Clone, Debug)]
struct CoolingScheduleClap(CoolingSchedule);
impl ValueEnum for CoolingScheduleClap {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self(CoolingSchedule::Exponential),
            Self(CoolingSchedule::Linear),
            Self(CoolingSchedule::Logarithmic),
            Self(CoolingSchedule::Quadratic),
        ]
    }
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self.0 {
            CoolingSchedule::Exponential => Some("exp".into()),
            CoolingSchedule::Linear => Some("lin".into()),
            CoolingSchedule::Logarithmic => Some("log".into()),
            CoolingSchedule::Quadratic => Some("quad".into()),
        }
    }
}

#[derive(Parser, Debug)]
struct FallbackArgs {
    test_cases: Vec<PathBuf>,
}

fn observation() -> (bool, Option<f64>) {
    (target::any_target_hit(), distance::current_distance())
}
fn reset_input() {
    beacon::begin_input();
}

#[no_mangle]
pub fn libafl_main() {
    let args = Args::try_parse().unwrap_or_else(|error| {
        if let Ok(fallback) = FallbackArgs::try_parse() {
            if !fallback.test_cases.is_empty() {
                run_testcases(&fallback.test_cases);
                exit(0);
            }
        }
        error.exit();
    });
    if let Err(error) = fuzz(args) {
        panic!("Halo fuzzer failed: {error}");
    }
}

fn run_testcases(files: &[impl AsRef<Path>]) {
    let args: Vec<String> = env::args().collect();
    let _ = libfuzzer_initialize(&args);
    for path in files {
        let mut input = Vec::new();
        File::open(path).unwrap().read_to_end(&mut input).unwrap();
        reset_input();
        libfuzzer_test_one_input(&input);
    }
}

fn fuzz(args: Args) -> Result<(), Error> {
    fs::create_dir_all(&args.output)?;
    if !args.input.is_dir() {
        return Err(Error::illegal_argument("seed directory is missing"));
    }
    let log = RefCell::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&args.logfile)?,
    );
    let shared: HaloShared = Arc::new(Mutex::new(HaloController::open(&args.output)?));
    let monitor_shared = shared.clone();
    let monitor = SimpleMonitor::with_user_monitor(
        move |line| {
            println!("{line}");
            let totals = &monitor_shared
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .engine
                .totals;
            let _ = writeln!(log.borrow_mut(),
                "{:?} {line} halo_observed={} halo_reached={} halo_generated={} halo_inferences={} halo_inference_ns={} halo_generation_ns={}",
                current_time(), totals.observed, totals.reached, totals.generated,
                totals.inferences, totals.inference_ns, totals.generation_ns);
        },
        true,
    );
    let mut shmem_provider = StdShMemProvider::new()?;
    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        Ok(value) => value,
        Err(Error::ShuttingDown) => return Ok(()),
        Err(error) => return Err(error),
    };
    let edges_observer = HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") });
    let time_observer = TimeObserver::new("time");
    let distance_observer = InProcessDistanceObserver::new("distance".into());
    let targets_observer =
        HitcountsMapObserver::new(unsafe { get_targets_map_observer("targets") });
    let halo_observer = HaloInputObserver::new(shared.clone(), reset_input, observation);

    let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
    let targets_feedback = MaxMapFeedback::new(&targets_observer);
    let calibration = CalibrationStage::new(&map_feedback);
    let mut feedback = feedback_or!(
        HaloMetadataFeedback::new(shared.clone()),
        map_feedback,
        TimeFeedback::with_observer(&time_observer),
        DistanceFeedback::with_observer(
            &distance_observer,
            Some(args.cooling_schedule.0),
            Duration::from_secs(args.time_to_exploit * 60),
        ),
        targets_feedback
    );
    let mut objective = CrashFeedback::new();
    let seed = args.halo_seed.unwrap_or_else(current_nanos);
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(seed),
            InMemoryOnDiskCorpus::<BytesInput>::new(args.output.join("queue")).unwrap(),
            OnDiskCorpus::new(args.output.join("crashes")).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });
    let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
        &mut state,
        &edges_observer,
        Some(PowerSchedule::FAST),
    ));
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let args_vec: Vec<String> = env::args().collect();
    let _ = libfuzzer_initialize(&args_vec);
    let mut harness = |input: &BytesInput| {
        libfuzzer_test_one_input(input.target_bytes().as_slice());
        ExitKind::Ok
    };
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(
                edges_observer,
                time_observer,
                distance_observer,
                targets_observer,
                halo_observer
            ),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?,
        Duration::from_millis(args.timeout),
    );
    if state.must_load_initial_inputs() {
        state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, &[args.input])?;
        println!(
            "Imported {} inputs; Halo RNG seed {seed}",
            state.corpus().count()
        );
    }
    if !args.show_target_output {
        let null_fd = File::open("/dev/null")?;
        #[cfg(unix)]
        {
            dup2(null_fd.as_raw_fd(), io::stdout().as_raw_fd())?;
            dup2(null_fd.as_raw_fd(), io::stderr().as_raw_fd())?;
        }
    }
    let halo_stage = StdMutationalStage::new(HaloMutator::new(shared.clone()));
    if args.halo_only {
        let mut stages = tuple_list!(calibration, halo_stage);
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    } else {
        // LibAFL havoc includes crossover, but no separate AFL++ splice cycle.
        // It is scheduled after invariant sampling and does not use MOPT.
        let havoc = StdMutationalStage::new(StdScheduledMutator::new(havoc_mutations()));
        let mut stages = tuple_list!(calibration, halo_stage, havoc);
        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    }
    let _ = shared
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .checkpoint();
    Ok(())
}
