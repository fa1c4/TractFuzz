//! Paper-based Halo input inference and generation for the LibAFLGo stack.
//! The original DIG and Vaidya-walk implementations are not publicly available.
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use libafl::{
    bolts::rands::Rand,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    impl_serdeany,
    inputs::{BytesInput, HasBytesVec, UsesInput},
    mutators::{MutationResult, Mutator},
    observers::{Observer, ObserversTuple},
    prelude::Named,
    state::{HasClientPerfMonitor, HasMetadata, HasRand},
    Error,
};
use serde::{Deserialize, Serialize};

const SCHEMA: u32 = 1;
const POOL_LIMIT: usize = 385;
const BYTE_LIMIT: usize = 256;
const POSITION_LIMIT: usize = 16;
const CANDIDATE_LIMIT: usize = 64;
const REINFER_EVERY: u64 = 64;

pub fn input_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HaloInputMetadata {
    pub schema: u32,
    pub hash: u64,
    pub length: usize,
    pub reached: bool,
    pub distance: Option<f64>,
    pub parent_hash: Option<u64>,
    pub invariant_ids: Vec<u64>,
    pub generation_ns: u64,
}
impl_serdeany!(HaloInputMetadata);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Observation {
    meta: HaloInputMetadata,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Predicate {
    Equal {
        at: usize,
        value: u8,
    },
    Interval {
        at: usize,
        lo: u8,
        hi: u8,
    },
    SumEqual {
        left: usize,
        right: usize,
        value: u16,
    },
    DifferenceEqual {
        left: usize,
        right: usize,
        value: i16,
    },
}

impl Predicate {
    fn holds(&self, bytes: &[u8]) -> bool {
        match *self {
            Self::Equal { at, value } => bytes.get(at) == Some(&value),
            Self::Interval { at, lo, hi } => bytes.get(at).is_some_and(|b| lo <= *b && *b <= hi),
            Self::SumEqual { left, right, value } => match (bytes.get(left), bytes.get(right)) {
                (Some(a), Some(b)) => u16::from(*a) + u16::from(*b) == value,
                _ => false,
            },
            Self::DifferenceEqual { left, right, value } => {
                match (bytes.get(left), bytes.get(right)) {
                    (Some(a), Some(b)) => i16::from(*a) - i16::from(*b) == value,
                    _ => false,
                }
            }
        }
    }

    fn positions(&self) -> (usize, Option<usize>) {
        match *self {
            Self::Equal { at, .. } | Self::Interval { at, .. } => (at, None),
            Self::SumEqual { left, right, .. } | Self::DifferenceEqual { left, right, .. } => {
                (left, Some(right))
            }
        }
    }

    fn apply<R: Rand>(&self, avoid: bool, bytes: &mut [u8], rng: &mut R) -> bool {
        let before = bytes.to_vec();
        if avoid {
            if !self.holds(bytes) {
                return false;
            }
            let (at, _) = self.positions();
            if at < bytes.len() {
                bytes[at] = bytes[at].wrapping_add(1 + rng.below(255) as u8);
            }
            return bytes != before;
        }
        match *self {
            Self::Equal { at, value } if at < bytes.len() => bytes[at] = value,
            Self::Interval { at, lo, hi } if at < bytes.len() => {
                bytes[at] = lo + rng.below(u64::from(hi - lo) + 1) as u8;
            }
            Self::SumEqual { left, right, value } if left < bytes.len() && right < bytes.len() => {
                let low = value.saturating_sub(255);
                let high = value.min(255);
                let a = low + rng.below(u64::from(high - low) + 1) as u16;
                bytes[left] = a as u8;
                bytes[right] = (value - a) as u8;
            }
            Self::DifferenceEqual { left, right, value }
                if left < bytes.len() && right < bytes.len() =>
            {
                let low = 0_i16.max(-value);
                let high = 255_i16.min(255 - value);
                if low <= high {
                    let b = low + rng.below((high - low + 1) as u64) as i16;
                    bytes[left] = (b + value) as u8;
                    bytes[right] = b as u8;
                }
            }
            _ => {}
        }
        if bytes == before && !bytes.is_empty() {
            let (one, two) = self.positions();
            let other = (0..bytes.len()).find(|p| *p != one && Some(*p) != two);
            if let Some(at) = other {
                bytes[at] = bytes[at].wrapping_add(1 + rng.below(255) as u8);
            }
        }
        bytes != before
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invariant {
    pub id: u64,
    pub predicate: Predicate,
    pub avoid: bool,
    pub discrimination: f64,
    pub attempts: u64,
    pub useful: u64,
}

impl Invariant {
    pub fn similarity(&self) -> f64 {
        (self.useful + 1) as f64 / (self.attempts + 2) as f64
    }

    fn weight(&self) -> f64 {
        self.similarity() * (0.05 + self.discrimination)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HaloTotals {
    pub observed: u64,
    pub reached: u64,
    pub generated: u64,
    pub inferences: u64,
    pub inference_ns: u64,
    pub generation_ns: u64,
}

#[derive(Clone, Debug)]
struct Pending {
    parent_hash: u64,
    parent_distance: Option<f64>,
    invariant_id: Option<u64>,
    generation_ns: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HaloEngine {
    schema: u32,
    reaching: VecDeque<Observation>,
    missing: VecDeque<Observation>,
    pub candidates: Vec<Invariant>,
    pub totals: HaloTotals,
    #[serde(skip)]
    pending: Option<Pending>,
    #[serde(skip)]
    last: Option<HaloInputMetadata>,
}

impl Default for HaloEngine {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            reaching: VecDeque::new(),
            missing: VecDeque::new(),
            candidates: Vec::new(),
            totals: HaloTotals::default(),
            pending: None,
            last: None,
        }
    }
}

impl HaloEngine {
    pub fn pool_sizes(&self) -> (usize, usize) {
        (self.reaching.len(), self.missing.len())
    }

    pub fn last_metadata(&self) -> Option<&HaloInputMetadata> {
        self.last.as_ref()
    }

    pub fn observe(&mut self, input: &[u8], reached: bool, distance: Option<f64>) {
        let hash = input_hash(input);
        let distance = distance.filter(|v| v.is_finite() && *v >= 0.0);
        let pending = self.pending.take();
        if let Some(ref generation) = pending {
            if let Some(id) = generation.invariant_id {
                if let Some(candidate) = self.candidates.iter_mut().find(|c| c.id == id) {
                    candidate.attempts += 1;
                    if reached
                        || matches!((distance, generation.parent_distance), (Some(now), Some(old)) if now < old)
                    {
                        candidate.useful += 1;
                    }
                }
            }
        }
        let meta = HaloInputMetadata {
            schema: SCHEMA,
            hash,
            length: input.len(),
            reached,
            distance,
            parent_hash: pending.as_ref().map(|g| g.parent_hash),
            invariant_ids: pending
                .as_ref()
                .and_then(|g| g.invariant_id)
                .into_iter()
                .collect(),
            generation_ns: pending.as_ref().map_or(0, |g| g.generation_ns),
        };
        self.last = Some(meta.clone());
        self.totals.observed += 1;
        self.totals.reached += u64::from(reached);
        let pool = if reached {
            &mut self.reaching
        } else {
            &mut self.missing
        };
        if !pool
            .iter()
            .any(|old| old.meta.hash == hash && old.meta.length == input.len())
        {
            pool.push_back(Observation {
                meta,
                bytes: input[..input.len().min(BYTE_LIMIT)].to_vec(),
            });
            if pool.len() > POOL_LIMIT {
                pool.pop_front();
            }
        }
        if self.totals.observed % REINFER_EVERY == 0 || (reached && self.reaching.len() == 1) {
            self.infer();
        }
    }

    fn ranked_groups(&self) -> (Vec<&Observation>, Vec<&Observation>, bool) {
        if self.reaching.len() >= 2 {
            let positive = self.reaching.iter().collect();
            let negative = self.missing.iter().collect();
            return (positive, negative, false);
        }
        let mut finite: Vec<_> = self
            .missing
            .iter()
            .filter(|o| o.meta.distance.is_some())
            .collect();
        finite.sort_by(|a, b| {
            a.meta
                .distance
                .unwrap()
                .total_cmp(&b.meta.distance.unwrap())
        });
        if finite.len() < 6 {
            return (Vec::new(), Vec::new(), false);
        }
        let count = (finite.len() / 3).max(2);
        let near = finite[..count].to_vec();
        let far = finite[finite.len() - count..].to_vec();
        (far, near, true)
    }

    pub fn infer(&mut self) {
        let start = Instant::now();
        let (source, opposite, avoid) = self.ranked_groups();
        // A single zero-length or truncated sample must not erase every byte
        // relation. Infer from the common-length majority and compare only
        // observations with enough bytes for those positions.
        let mut lengths: Vec<_> = source.iter().map(|o| o.bytes.len()).collect();
        lengths.sort_unstable();
        let cutoff = lengths.get(lengths.len() / 10).copied().unwrap_or(0).max(1);
        let source: Vec<_> = source
            .into_iter()
            .filter(|o| o.bytes.len() >= cutoff)
            .collect();
        let opposite: Vec<_> = opposite
            .into_iter()
            .filter(|o| o.bytes.len() >= cutoff)
            .collect();
        if source.len() < 2 || opposite.is_empty() {
            return;
        }
        let max_len = source
            .iter()
            .map(|o| o.bytes.len())
            .min()
            .unwrap_or(0)
            .min(BYTE_LIMIT);
        let mut positions = Vec::new();
        for at in 0..max_len {
            let mean_a =
                source.iter().map(|o| f64::from(o.bytes[at])).sum::<f64>() / source.len() as f64;
            let mean_b = opposite.iter().map(|o| f64::from(o.bytes[at])).sum::<f64>()
                / opposite.len() as f64;
            let a_min = source.iter().map(|o| o.bytes[at]).min().unwrap();
            let a_max = source.iter().map(|o| o.bytes[at]).max().unwrap();
            let b_min = opposite.iter().map(|o| o.bytes[at]).min().unwrap();
            let b_max = opposite.iter().map(|o| o.bytes[at]).max().unwrap();
            let gap = if a_max < b_min {
                b_min - a_max
            } else if b_max < a_min {
                a_min - b_max
            } else {
                0
            };
            let score = (mean_a - mean_b).abs() + f64::from(gap);
            if score > 0.0 {
                positions.push((at, score));
            }
        }
        positions.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        positions.truncate(POSITION_LIMIT);
        let old: HashMap<u64, (u64, u64)> = self
            .candidates
            .iter()
            .map(|c| (c.id, (c.attempts, c.useful)))
            .collect();
        let mut candidates = Vec::new();
        let mut add = |predicate: Predicate| {
            if !source.iter().all(|o| predicate.holds(&o.bytes)) {
                return;
            }
            let rejected = opposite
                .iter()
                .filter(|o| !predicate.holds(&o.bytes))
                .count();
            if rejected == 0 {
                return;
            }
            let id = input_hash(format!("{predicate:?}:{avoid}").as_bytes());
            if candidates.iter().any(|c: &Invariant| c.id == id) {
                return;
            }
            let (attempts, useful) = old.get(&id).copied().unwrap_or((0, 0));
            candidates.push(Invariant {
                id,
                predicate,
                avoid,
                discrimination: rejected as f64 / opposite.len() as f64,
                attempts,
                useful,
            });
        };
        for &(at, _) in &positions {
            let lo = source.iter().map(|o| o.bytes[at]).min().unwrap();
            let hi = source.iter().map(|o| o.bytes[at]).max().unwrap();
            if lo == hi {
                add(Predicate::Equal { at, value: lo });
            } else if hi - lo <= 64 {
                add(Predicate::Interval { at, lo, hi });
            }
        }
        for (i, &(left, _)) in positions.iter().enumerate() {
            for &(right, _) in positions.iter().skip(i + 1) {
                let sum = u16::from(source[0].bytes[left]) + u16::from(source[0].bytes[right]);
                add(Predicate::SumEqual {
                    left,
                    right,
                    value: sum,
                });
                let difference =
                    i16::from(source[0].bytes[left]) - i16::from(source[0].bytes[right]);
                add(Predicate::DifferenceEqual {
                    left,
                    right,
                    value: difference,
                });
            }
        }
        candidates.sort_by(|a, b| {
            b.discrimination
                .total_cmp(&a.discrimination)
                .then(a.id.cmp(&b.id))
        });
        candidates.truncate(CANDIDATE_LIMIT);
        self.candidates = candidates;
        self.totals.inferences += 1;
        self.totals.inference_ns += start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    }

    pub fn generate<R: Rand>(&mut self, base: &mut Vec<u8>, rng: &mut R) -> Option<u64> {
        let start = Instant::now();
        let parent_hash = input_hash(base);
        let parent_distance = self
            .reaching
            .iter()
            .chain(self.missing.iter())
            .find(|o| o.meta.hash == parent_hash && o.meta.length == base.len())
            .and_then(|o| o.meta.distance);
        if base.is_empty() {
            base.push(rng.below(256) as u8);
        }
        let total: f64 = self
            .candidates
            .iter()
            .filter(|c| c.predicate.positions().0 < base.len())
            .map(Invariant::weight)
            .sum();
        let mut selected = None;
        if total > 0.0 {
            let mut draw = (rng.below(1_000_000) as f64 / 1_000_000.0) * total;
            for candidate in &self.candidates {
                if candidate.predicate.positions().0 >= base.len() {
                    continue;
                }
                draw -= candidate.weight();
                if draw <= 0.0 {
                    selected = Some((candidate.id, candidate.predicate.clone(), candidate.avoid));
                    break;
                }
            }
        }
        let mut chosen = None;
        if let Some((id, predicate, avoid)) = selected {
            if predicate.apply(avoid, base, rng) {
                chosen = Some(id);
            }
        }
        if chosen.is_none() {
            let at = rng.below(base.len() as u64) as usize;
            base[at] = base[at].wrapping_add(1 + rng.below(255) as u8);
        }
        let generation_ns = start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        self.totals.generated += 1;
        self.totals.generation_ns += generation_ns;
        self.pending = Some(Pending {
            parent_hash,
            parent_distance,
            invariant_id: chosen,
            generation_ns,
        });
        chosen
    }
}

#[derive(Debug)]
pub struct HaloController {
    pub engine: HaloEngine,
    path: PathBuf,
    input_trace: BufWriter<File>,
    invariant_trace: BufWriter<File>,
    last_inference: u64,
}

impl HaloController {
    pub fn open(directory: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(directory)?;
        let path = directory.join("halo-checkpoint-v1.json");
        let engine = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<HaloEngine>(&bytes).ok())
            .filter(|state| state.schema == SCHEMA)
            .unwrap_or_default();
        let input_path = directory.join("halo-inputs-v1.tsv");
        let invariant_path = directory.join("halo-invariants-v1.tsv");
        let fresh_inputs = !input_path.exists() || input_path.metadata()?.len() == 0;
        let fresh_invariants = !invariant_path.exists() || invariant_path.metadata()?.len() == 0;
        let mut input_trace = BufWriter::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(input_path)?,
        );
        let mut invariant_trace = BufWriter::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(invariant_path)?,
        );
        if fresh_inputs {
            writeln!(input_trace, "schema\thash\tlength\treached\tdistance\tparent_hash\tinvariant_ids\tgeneration_ns")?;
        }
        if fresh_invariants {
            writeln!(
                invariant_trace,
                "observation\tid\tpredicate\tavoid\tdiscrimination\tattempts\tuseful\tsimilarity"
            )?;
        }
        let last_inference = engine.totals.inferences;
        Ok(Self {
            engine,
            path,
            input_trace,
            invariant_trace,
            last_inference,
        })
    }

    pub fn observe(&mut self, bytes: &[u8], reached: bool, distance: Option<f64>) {
        self.engine.observe(bytes, reached, distance);
        if let Some(meta) = self.engine.last_metadata() {
            let ids = meta
                .invariant_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(";");
            let _ = writeln!(
                self.input_trace,
                "{}\t{:016x}\t{}\t{}\t{}\t{}\t{}\t{}",
                SCHEMA,
                meta.hash,
                meta.length,
                u8::from(meta.reached),
                meta.distance.map_or_else(|| "?".into(), |d| d.to_string()),
                meta.parent_hash
                    .map_or_else(|| "?".into(), |h| format!("{h:016x}")),
                ids,
                meta.generation_ns
            );
        }
        if self.engine.totals.inferences != self.last_inference {
            self.last_inference = self.engine.totals.inferences;
            for candidate in &self.engine.candidates {
                let _ = writeln!(
                    self.invariant_trace,
                    "{}\t{:016x}\t{:?}\t{}\t{}\t{}\t{}\t{}",
                    self.engine.totals.observed,
                    candidate.id,
                    candidate.predicate,
                    u8::from(candidate.avoid),
                    candidate.discrimination,
                    candidate.attempts,
                    candidate.useful,
                    candidate.similarity()
                );
            }
        }
        if self.engine.totals.observed % REINFER_EVERY == 0 {
            let _ = self.checkpoint();
        }
    }

    pub fn checkpoint(&mut self) -> std::io::Result<()> {
        self.input_trace.flush()?;
        self.invariant_trace.flush()?;
        let data = serde_json::to_vec(&self.engine)?;
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, data)?;
        fs::rename(temporary, &self.path)
    }
}

impl Drop for HaloController {
    fn drop(&mut self) {
        let _ = self.checkpoint();
    }
}

pub type HaloShared = Arc<Mutex<HaloController>>;

type HaloObservationConfig = (HaloShared, fn(), fn() -> (bool, Option<f64>));
static HALO_OBSERVATION_CONFIG: OnceLock<HaloObservationConfig> = OnceLock::new();

fn observer_shared() -> HaloShared {
    HALO_OBSERVATION_CONFIG
        .get()
        .expect("Halo observer configured")
        .0
        .clone()
}
fn observer_reset() -> fn() {
    HALO_OBSERVATION_CONFIG
        .get()
        .expect("Halo observer configured")
        .1
}
fn observer_snapshot() -> fn() -> (bool, Option<f64>) {
    HALO_OBSERVATION_CONFIG
        .get()
        .expect("Halo observer configured")
        .2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HaloInputObserver {
    name: String,
    #[serde(skip, default = "observer_shared")]
    shared: HaloShared,
    #[serde(skip, default = "observer_reset")]
    reset: fn(),
    #[serde(skip, default = "observer_snapshot")]
    snapshot: fn() -> (bool, Option<f64>),
}

impl HaloInputObserver {
    pub fn new(shared: HaloShared, reset: fn(), snapshot: fn() -> (bool, Option<f64>)) -> Self {
        let _ = HALO_OBSERVATION_CONFIG.set((shared.clone(), reset, snapshot));
        Self {
            name: "halo-inputs".into(),
            shared,
            reset,
            snapshot,
        }
    }
}

impl Named for HaloInputObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S: UsesInput<Input = BytesInput>> Observer<S> for HaloInputObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &BytesInput) -> Result<(), Error> {
        (self.reset)();
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        input: &BytesInput,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        let (reached, distance) = (self.snapshot)();
        self.shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe(input.bytes(), reached, distance);
        Ok(())
    }
}

pub struct HaloMetadataFeedback<S> {
    shared: HaloShared,
    last: Option<HaloInputMetadata>,
    phantom: PhantomData<S>,
}

impl<S> fmt::Debug for HaloMetadataFeedback<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HaloMetadataFeedback").finish()
    }
}

impl<S> HaloMetadataFeedback<S> {
    pub fn new(shared: HaloShared) -> Self {
        Self {
            shared,
            last: None,
            phantom: PhantomData,
        }
    }
}

impl<S> Named for HaloMetadataFeedback<S> {
    fn name(&self) -> &str {
        "halo-metadata"
    }
}

impl<S> Feedback<S> for HaloMetadataFeedback<S>
where
    S: UsesInput<Input = BytesInput> + HasClientPerfMonitor,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &BytesInput,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.last = self
            .shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .engine
            .last_metadata()
            .filter(|m| m.hash == input_hash(input.bytes()) && m.length == input.bytes().len())
            .cloned();
        Ok(false)
    }

    fn append_metadata<OT>(
        &mut self,
        _state: &mut S,
        _observers: &OT,
        testcase: &mut Testcase<BytesInput>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
        if let Some(meta) = self.last.take() {
            testcase.add_metadata(meta);
        }
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &BytesInput) -> Result<(), Error> {
        self.last = None;
        Ok(())
    }
}

#[derive(Debug)]
pub struct HaloMutator {
    shared: HaloShared,
}

impl HaloMutator {
    pub fn new(shared: HaloShared) -> Self {
        Self { shared }
    }
}

impl<S: HasRand> Mutator<BytesInput, S> for HaloMutator {
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .engine
            .generate(input.bytes_mut(), state.rand_mut());
        Ok(MutationResult::Mutated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libafl::bolts::{current_nanos, rands::StdRand};

    #[test]
    fn infers_and_samples_equality_interval_and_linear_relation() {
        let mut engine = HaloEngine::default();
        for a in 3..9_u8 {
            engine.observe(&[b'H', a, 20 - a, 0], true, Some(1.0));
        }
        for a in 30..38_u8 {
            engine.observe(&[b'X', a, a, 0], false, Some(20.0));
        }
        engine.infer();
        assert!(engine
            .candidates
            .iter()
            .any(|c| c.predicate == Predicate::Equal { at: 0, value: b'H' }));
        assert!(engine.candidates.iter().any(|c| c.predicate
            == Predicate::Interval {
                at: 1,
                lo: 3,
                hi: 8
            }));
        assert!(engine.candidates.iter().any(|c| c.predicate
            == Predicate::SumEqual {
                left: 1,
                right: 2,
                value: 20
            }));
        let mut rng = StdRand::with_seed(17);
        let mut hits = 0;
        for _ in 0..200 {
            let mut bytes = vec![b'X', 50, 50, 0];
            let id = engine.generate(&mut bytes, &mut rng);
            if let Some(id) = id {
                let candidate = engine.candidates.iter().find(|c| c.id == id).unwrap();
                assert!(candidate.predicate.holds(&bytes));
                hits += 1;
            }
        }
        assert!(hits > 100);
    }

    #[test]
    fn sparse_positive_and_misleading_correlation_are_visible() {
        let mut engine = HaloEngine::default();
        for value in 0..18_u8 {
            engine.observe(&[value, 0], false, Some(f64::from(30 - value)));
        }
        engine.infer();
        assert!(!engine.candidates.is_empty());
        assert!(engine.candidates.iter().all(|c| c.avoid));
        engine.observe(&[19, 1], true, Some(1.0));
        engine.infer();
        assert!(engine.candidates.iter().all(|c| c.avoid)); // one positive is insufficient
        engine.observe(&[20, 0], true, Some(1.0));
        engine.infer();
        assert!(engine.candidates.iter().any(|c| !c.avoid));
        // A misleading byte that differs in training samples is heuristic evidence only.
        assert!(engine
            .candidates
            .iter()
            .any(|c| matches!(c.predicate, Predicate::Interval { at: 0, .. })));
    }

    #[test]
    fn truncated_negative_does_not_clear_byte_invariants() {
        let mut engine = HaloEngine::default();
        engine.observe(&[b'H', 4, 16, 0], true, Some(1.0));
        engine.observe(&[b'H', 5, 15, 0], true, Some(1.0));
        engine.observe(&[], false, None);
        engine.observe(&[b'X', 30, 30, 0], false, Some(30.0));
        engine.infer();
        assert!(engine
            .candidates
            .iter()
            .any(|c| c.predicate == Predicate::Equal { at: 0, value: b'H' }));
    }

    #[test]
    fn checkpoint_restores_observation_pools() {
        let directory = std::env::temp_dir().join(format!(
            "halo-checkpoint-{}-{}",
            std::process::id(),
            current_nanos()
        ));
        {
            let mut controller = HaloController::open(&directory).unwrap();
            controller.observe(&[b'H', 4, 16], true, Some(1.0));
            controller.observe(&[b'X', 30, 30], false, Some(30.0));
            controller.checkpoint().unwrap();
        }
        let restored = HaloController::open(&directory).unwrap();
        assert_eq!(restored.engine.totals.observed, 2);
        assert_eq!(restored.engine.pool_sizes(), (1, 1));
        drop(restored);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
