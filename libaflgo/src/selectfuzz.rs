//! SelectFuzz queue and mutation energy weighting.
use std::{
    env,
    fs::{File, OpenOptions},
    io::Write,
    sync::{Mutex, OnceLock},
};

use libafl::{
    feedbacks::MapNoveltiesMetadata,
    prelude::Testcase,
    schedulers::{TestcaseScore, WeightedScheduler},
    stages::PowerMutationalStage,
    state::{HasCorpus, HasMetadata, HasNamedMetadata},
    Error,
};

use crate::{DistancePowerTestcaseScore, DistanceTestcaseMetadata, DistanceWeightTestcaseScore};

static QUEUE_TRACE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn trace_queue<I: libafl::inputs::Input>(entry: &Testcase<I>, score: f64) {
    let trace = QUEUE_TRACE.get_or_init(|| {
        let path = env::var_os("SELECTFUZZ_QUEUE_TRACE")?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        if file.metadata().map(|m| m.len() == 0).unwrap_or(false) {
            let _ = writeln!(file, "filename,novel_edges,distance,queue_score");
        }
        Some(Mutex::new(file))
    });
    if let Some(trace) = trace {
        if let Ok(mut file) = trace.lock() {
            let novel = entry
                .metadata::<MapNoveltiesMetadata>()
                .map(|m| m.list.len())
                .unwrap_or(0);
            let distance = entry
                .metadata::<DistanceTestcaseMetadata>()
                .map(|m| m.distance())
                .unwrap_or(f64::NAN);
            let name = entry.filename().as_deref().unwrap_or("?").replace(',', "_");
            let _ = writeln!(file, "{name},{novel},{distance},{score}");
        }
    }
}

fn novelty_factor<I: libafl::inputs::Input>(entry: &Testcase<I>) -> f64 {
    let novel = entry
        .metadata::<MapNoveltiesMetadata>()
        .map(|m| m.list.len())
        .unwrap_or(0);
    if novel == 0 {
        1.0
    } else {
        (1.0 + novel as f64).min(32.0)
    }
}

pub struct SelectFuzzQueueScore;
impl<S: HasCorpus + HasMetadata> TestcaseScore<S> for SelectFuzzQueueScore {
    fn compute(state: &S, entry: &mut Testcase<S::Input>) -> Result<f64, Error> {
        let factor = novelty_factor(entry);
        let score = DistanceWeightTestcaseScore::compute(state, entry)? * factor;
        trace_queue(entry, score);
        Ok(score)
    }
}

pub struct SelectFuzzEnergyScore;
impl<S: HasCorpus + HasMetadata + HasNamedMetadata> TestcaseScore<S> for SelectFuzzEnergyScore {
    fn compute(state: &S, entry: &mut Testcase<S::Input>) -> Result<f64, Error> {
        let factor = novelty_factor(entry);
        Ok((DistancePowerTestcaseScore::compute(state, entry)? * factor).min(6400.0))
    }
}

pub type SelectFuzzWeightedScheduler<O, S> = WeightedScheduler<SelectFuzzQueueScore, O, S>;
pub type SelectFuzzPowerMutationalStage<E, EM, I, M, Z> =
    PowerMutationalStage<E, SelectFuzzEnergyScore, EM, I, M, Z>;
