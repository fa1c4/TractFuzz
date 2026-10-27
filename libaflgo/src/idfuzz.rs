//! IDFuzz adaptation: mutation history, learned dominator labels, and byte-guided mutation.
use std::{collections::HashMap, fs::{self, File, OpenOptions}, io::{BufRead, BufReader, Write},
    path::{Path, PathBuf}, process::{Child, Command}, sync::{Arc, Mutex, OnceLock}, time::Instant};

use libafl::{bolts::rands::Rand, executors::ExitKind, inputs::{BytesInput, HasBytesVec, UsesInput},
    mutators::{MutationResult, Mutator}, observers::Observer, prelude::Named,
    state::HasRand, Error};
use serde::{Deserialize, Serialize};

pub const DOM_SIZE: usize = 256;
pub const MODEL_BYTES: usize = 1024;
const MAX_RECORDS: u64 = 20000;
const RETRAIN_EVERY: u64 = 512;

pub fn hash(bytes: &[u8]) -> String {
    let mut h = 0xcbf29ce484222325u64;
    for b in bytes { h = (h ^ u64::from(*b)).wrapping_mul(0x100000001b3); }
    format!("{h:016x}")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mutation { pub parent: String, pub operation: String, pub offsets: Vec<usize>,
    pub model_version: Option<u64> }

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Totals { pub observed: u64, pub retained: u64, pub reached: u64,
    pub generated: u64, pub model_calls: u64, pub model_failures: u64,
    pub model_completed: u64, pub train_ns: u64, pub fallback: u64,
    pub long_inputs: u64, pub dropped_records: u64 }

#[derive(Serialize)]
struct Record<'a> { schema: u8, hash: String, input_len: usize, input_hex: String,
    parent: Option<&'a str>, operation: Option<&'a str>, offsets: Vec<usize>,
    dominators: Vec<usize>, branches: Vec<(usize, f32)>,
    distance: Option<f64>, target_hit: bool,
    exit: &'a str, model_version: Option<u64> }

#[derive(Deserialize)]
struct ModelResult { schema: u8, version: u64, rankings: HashMap<String, Vec<usize>>,
    modes: HashMap<String, String>, fields: HashMap<String, Vec<Field>> }
#[derive(Clone, Debug, Deserialize)]
struct Field { start: usize, length: usize }

#[derive(Debug)]
pub struct Controller {
    output: PathBuf, writer: File, pending: Option<Mutation>,
    rankings: HashMap<String, Vec<usize>>, modes: HashMap<String, String>,
    fields: HashMap<String, Vec<Field>>, cursor: HashMap<String, usize>,
    version: Option<u64>, control: bool, active: Option<(Child, Instant)>,
    auto_checkpoint: bool, pub totals: Totals,
}
pub type Shared = Arc<Mutex<Controller>>;

impl Controller {
    pub fn open(output: &Path) -> Result<Self, Error> {
        fs::create_dir_all(output)?;
        let records_path = output.join("idfuzz-records-v1.jsonl");
        let mut totals = fs::read(output.join("idfuzz-totals-v1.json"))
            .ok().and_then(|bytes| serde_json::from_slice::<Totals>(&bytes).ok())
            .unwrap_or_default();
        if let Ok(records) = File::open(&records_path) {
            let on_disk = BufReader::new(records).lines().count() as u64;
            totals.retained = totals.retained.max(on_disk);
            totals.observed = totals.observed.max(totals.retained);
        }
        let writer = OpenOptions::new().create(true).append(true)
            .open(records_path)?;
        let mut controller = Self { output: output.to_owned(), writer, pending: None,
            rankings: HashMap::new(), modes: HashMap::new(), fields: HashMap::new(),
            cursor: HashMap::new(), version: None,
            control: false, active: None, auto_checkpoint: true, totals };
        controller.reload();
        Ok(controller)
    }
    pub fn set_control(&mut self, value: bool) { self.control = value; }
    /// The restart broker is forked from the first process. Only a worker may
    /// checkpoint counters; otherwise the broker can overwrite newer totals.
    pub fn prepare_for_restart_manager(&mut self) { self.auto_checkpoint = false; }
    pub fn resume_after_fork(&mut self) {
        self.totals = fs::read(self.output.join("idfuzz-totals-v1.json"))
            .ok().and_then(|bytes| serde_json::from_slice::<Totals>(&bytes).ok())
            .unwrap_or_default();
        if let Ok(records) = File::open(self.output.join("idfuzz-records-v1.jsonl")) {
            let on_disk = BufReader::new(records).lines().count() as u64;
            self.totals.retained = self.totals.retained.max(on_disk);
            self.totals.observed = self.totals.observed.max(on_disk);
        }
        self.reload();
        self.auto_checkpoint = true;
    }
    fn reload(&mut self) {
        let path = self.output.join("idfuzz-rankings-v1.json");
        if let Ok(data) = fs::read(path) {
            if let Ok(result) = serde_json::from_slice::<ModelResult>(&data) {
                if result.schema == 1 { self.version = Some(result.version);
                    self.rankings = result.rankings;
                    self.modes = result.modes;
                    self.fields = result.fields; }
            }
        }
    }
    pub fn observe(&mut self, input: &[u8], dom: &[u8], reached: bool,
                   distance: Option<f64>, exit: &ExitKind) {
        self.totals.observed += 1;
        self.totals.reached += u64::from(reached);
        self.totals.long_inputs += u64::from(input.len() > MODEL_BYTES);
        if self.totals.observed % 1024 == 0 { let _ = self.checkpoint(); }
        if self.control { return; }
        if self.totals.observed % 64 == 0 { self.poll_train(); }
        let pending = self.pending.take();
        let (regular_stride, reaching_stride) =
            if self.version.is_some() { (256, 64) } else { (32, 8) };
        if self.totals.retained >= MAX_RECORDS ||
           (self.totals.observed > 256 && self.totals.observed % regular_stride != 0 &&
            !(reached && self.totals.observed % reaching_stride == 0)) {
            self.totals.dropped_records += 1;
            return;
        }
        let mut input_hex = String::with_capacity(input.len().min(MODEL_BYTES) * 2);
        for b in input.iter().take(MODEL_BYTES) {
            use std::fmt::Write;
            let _ = write!(input_hex, "{b:02x}");
        }
        let record = Record { schema: 1, hash: hash(input), input_len: input.len(),
            input_hex, parent: pending.as_ref().map(|x| x.parent.as_str()),
            operation: pending.as_ref().map(|x| x.operation.as_str()),
            offsets: pending.as_ref().map_or_else(Vec::new, |x| x.offsets.clone()),
            dominators: dom.iter().enumerate().filter_map(|(i, v)| (*v == 255).then_some(i)).collect(),
            branches: dom.iter().enumerate().filter_map(|(i, v)|
                (*v > 0 && *v < 255).then_some((i, f32::from(*v) / 255.0))).collect(),
            distance: distance.filter(|x| x.is_finite()), target_hit: reached,
            exit: match exit { ExitKind::Ok => "ok", ExitKind::Crash => "crash",
                ExitKind::Timeout => "timeout", _ => "other" },
            model_version: pending.as_ref().and_then(|x| x.model_version) };
        if serde_json::to_writer(&mut self.writer, &record).is_ok() &&
            self.writer.write_all(b"\n").is_ok() {
            self.totals.retained += 1;
        }
        if self.totals.retained == 128 ||
           (self.totals.retained >= RETRAIN_EVERY &&
            self.totals.retained % RETRAIN_EVERY == 0) {
            if self.active.is_none() { self.train(); }
            let _ = self.checkpoint();
        }
    }
    fn train(&mut self) {
        let script = std::env::var_os("IDFUZZ_MODEL_SCRIPT")
            .map(PathBuf::from).unwrap_or_else(|| PathBuf::from("scripts/idfuzz_model.py"));
        let _ = self.writer.flush();
        let child = Command::new("python3").arg(script)
            .env("OPENBLAS_NUM_THREADS", "1")
            .arg("--records").arg(self.output.join("idfuzz-records-v1.jsonl"))
            .arg("--output").arg(self.output.join("idfuzz-rankings-v1.json"))
            .arg("--checkpoint").arg(self.output.join("idfuzz-model-v1.npz"))
            .arg("--seed").arg("1337")
            .stdout(OpenOptions::new().create(true).append(true).open(
                self.output.join("idfuzz-training.log")).ok().unwrap_or_else(|| File::create("/dev/null").unwrap()))
            .stderr(OpenOptions::new().create(true).append(true).open(
                self.output.join("idfuzz-training.err")).ok().unwrap_or_else(|| File::create("/dev/null").unwrap()))
            .spawn();
        self.totals.model_calls += 1;
        match child {
            Ok(child) => self.active = Some((child, Instant::now())),
            Err(_) => self.totals.model_failures += 1,
        }
        let _ = self.checkpoint();
    }
    fn poll_train(&mut self) {
        let Some((child, started)) = self.active.as_mut() else { return; };
        match child.try_wait() {
            Ok(Some(status)) => {
                self.totals.train_ns += started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                self.totals.model_completed += 1;
                if status.success() { self.reload(); }
                else { self.totals.model_failures += 1; }
                self.active = None;
                let _ = self.checkpoint();
            }
            Ok(None) => {}
            Err(_) => { self.totals.model_failures += 1; self.active = None; }
        }
    }
    pub fn mutate<R: Rand>(&mut self, bytes: &mut [u8], rng: &mut R) -> bool {
        if bytes.is_empty() { self.totals.fallback += 1; return false; }
        let parent = hash(bytes);
        let Some(ranking) = self.rankings.get(&parent) else {
            self.totals.fallback += 1; return false;
        };
        let eligible: Vec<_> = ranking.iter().copied().filter(|i| *i < bytes.len() && *i < MODEL_BYTES).collect();
        if eligible.is_empty() { self.totals.fallback += 1; return false; }
        let cursor = self.cursor.entry(parent.clone()).or_default();
        let mode = self.modes.get(&parent).map(String::as_str).unwrap_or("aggressive");
        let mut offsets = Vec::new();
        let operation: String;
        let fields = self.fields.get(&parent);
        let field = if mode == "aggressive" && *cursor % 4 != 0 {
            fields.and_then(|fs| fs.get((*cursor / 4) % fs.len().max(1)))
        } else { None };
        if let Some(field) = field.filter(|f| f.start + f.length <= bytes.len()) {
            let values16 = [0u16, 1, 255, 256, 32767, 65535];
            let values32 = [0u32, 1, 255, 65535, 0x80000000, 0xffffffff];
            let value = if field.length == 2 {
                u32::from(values16[(*cursor / 4) % values16.len()])
            } else { values32[(*cursor / 4) % values32.len()] };
            let replacement = value.to_le_bytes();
            let before = bytes[field.start..field.start + field.length].to_vec();
            bytes[field.start..field.start + field.length]
                .copy_from_slice(&replacement[..field.length]);
            if bytes[field.start..field.start + field.length] == before {
                bytes[field.start] ^= 1;
            }
            offsets.extend(field.start..field.start + field.length);
            operation = format!("gradient-field-{}", field.length);
        } else {
            let offset = eligible[*cursor / 4 % eligible.len()];
            let old = bytes[offset];
            let mut replacement = if mode == "conservative" {
                rng.below(256) as u8
            } else { ((*cursor / 4) % 256) as u8 };
            if replacement == old { replacement = old.wrapping_add(1 + rng.below(255) as u8); }
            bytes[offset] = replacement;
            offsets.push(offset);
            operation = if mode == "conservative" { "conservative-noncritical-byte".into() }
                        else { "gradient-byte-enumeration".into() };
        }
        *cursor += 1;
        self.pending = Some(Mutation { parent, operation, offsets, model_version: self.version });
        self.totals.generated += 1;
        true
    }
    pub fn checkpoint(&mut self) -> Result<(), Error> {
        self.writer.flush()?;
        fs::write(self.output.join("idfuzz-totals-v1.json"),
                  serde_json::to_vec_pretty(&self.totals).map_err(|e| Error::illegal_state(e.to_string()))?)?;
        Ok(())
    }
}
impl Drop for Controller {
    fn drop(&mut self) { if self.auto_checkpoint { let _ = self.checkpoint(); } }
}

type ObservationConfig = (Shared, fn(), fn() -> (bool, Option<f64>, Vec<u8>));
static OBSERVATION_CONFIG: OnceLock<ObservationConfig> = OnceLock::new();
fn observer_shared() -> Shared { OBSERVATION_CONFIG.get().expect("IDFuzz configured").0.clone() }
fn observer_reset() -> fn() { OBSERVATION_CONFIG.get().expect("IDFuzz configured").1 }
fn observer_snapshot() -> fn() -> (bool, Option<f64>, Vec<u8>) {
    OBSERVATION_CONFIG.get().expect("IDFuzz configured").2
}
#[derive(Debug, Serialize, Deserialize)]
pub struct InputObserver { name: String,
    #[serde(skip, default = "observer_shared")]
    shared: Shared,
    #[serde(skip, default = "observer_reset")]
    reset: fn(),
    #[serde(skip, default = "observer_snapshot")]
    snapshot: fn() -> (bool, Option<f64>, Vec<u8>) }
impl InputObserver { pub fn new(shared: Shared, reset: fn(),
    snapshot: fn() -> (bool, Option<f64>, Vec<u8>)) -> Self {
    let _ = OBSERVATION_CONFIG.set((shared.clone(), reset, snapshot));
    Self { name: "idfuzz-inputs".into(), shared, reset, snapshot }
} }
impl Named for InputObserver { fn name(&self) -> &str { &self.name } }
impl<S: UsesInput<Input=BytesInput>> Observer<S> for InputObserver {
    fn pre_exec(&mut self, _: &mut S, _: &BytesInput) -> Result<(), Error> { (self.reset)(); Ok(()) }
    fn post_exec(&mut self, _: &mut S, input: &BytesInput, exit: &ExitKind) -> Result<(), Error> {
        let (hit, dist, dom) = (self.snapshot)();
        self.shared.lock().unwrap().observe(input.bytes(), &dom, hit, dist, exit);
        Ok(())
    }
}
#[derive(Debug)]
pub struct GuidedMutator { shared: Shared }
impl GuidedMutator { pub fn new(shared: Shared) -> Self { Self { shared } } }
impl<S: HasRand> Mutator<BytesInput, S> for GuidedMutator {
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput, _: i32)
        -> Result<MutationResult, Error> {
        if self.shared.lock().unwrap().mutate(input.bytes_mut(), state.rand_mut()) {
            Ok(MutationResult::Mutated)
        } else { Ok(MutationResult::Skipped) }
    }
}
