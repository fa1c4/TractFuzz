use std::sync::atomic::{AtomicU64, Ordering};

use libafl::prelude::{ExitKind, Named, Observer, UsesInput};
use libafl_targets::{edges_map_mut_ptr, edges_max_num};
use serde::{Deserialize, Serialize};

use libaflgo::DistanceObserver;

static MIN_DISTANCE: AtomicU64 = AtomicU64::new(u64::MAX);
static BEST_DISTANCE: AtomicU64 = AtomicU64::new(u64::MAX);
static DISTANCE_IMPROVEMENTS: AtomicU64 = AtomicU64::new(0);
static EXECUTIONS: AtomicU64 = AtomicU64::new(0);
static PROBES: AtomicU64 = AtomicU64::new(0);
static mut PREVIOUS: u32 = 0;

pub fn begin_input() {
    MIN_DISTANCE.store(u64::MAX, Ordering::Relaxed);
    unsafe {
        PREVIOUS = 0;
    }
    EXECUTIONS.fetch_add(1, Ordering::Relaxed);
    crate::beacon::begin_input(); // Also resets Magma canaries between inputs.
}

pub fn totals() -> (u64, u64, u64) {
    (
        EXECUTIONS.load(Ordering::Relaxed),
        PROBES.load(Ordering::Relaxed),
        DISTANCE_IMPROVEMENTS.load(Ordering::Relaxed),
    )
}

#[no_mangle]
pub extern "C" fn __selectfuzz_trace_bb(id: u32, distance_milli: u64) {
    if id == 0 {
        return;
    }
    PROBES.fetch_add(1, Ordering::Relaxed);
    if distance_milli != 0 {
        MIN_DISTANCE.fetch_min(distance_milli, Ordering::Relaxed);
    }
    // Coverage counts transitions between selected basic blocks only. The
    // zeroth predecessor marks first entry and is reset for every input.
    unsafe {
        let index =
            ((PREVIOUS.rotate_left(5) ^ id.wrapping_mul(0x9e3779b1)) as usize) % edges_max_num();
        let cell = edges_map_mut_ptr().add(index);
        *cell = (*cell).saturating_add(1);
        PREVIOUS = id;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SelectFuzzObserver {
    name: String,
    distance: f64,
}

impl SelectFuzzObserver {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            distance: f64::NAN,
        }
    }
}

impl Named for SelectFuzzObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S: UsesInput> DistanceObserver<S> for SelectFuzzObserver {
    fn distance(&self) -> f64 {
        self.distance
    }
}

impl<S: UsesInput> Observer<S> for SelectFuzzObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), libafl::Error> {
        begin_input();
        self.distance = f64::NAN;
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl::Error> {
        let d = MIN_DISTANCE.load(Ordering::Relaxed);
        if d < BEST_DISTANCE.fetch_min(d, Ordering::Relaxed) {
            DISTANCE_IMPROVEMENTS.fetch_add(1, Ordering::Relaxed);
        }
        self.distance = if d == u64::MAX {
            f64::NAN
        } else {
            d as f64 / 1000.0
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_distance_and_reset() {
        begin_input();
        __selectfuzz_trace_bb(1, 9000);
        __selectfuzz_trace_bb(2, 2000);
        __selectfuzz_trace_bb(3, 7000);
        assert_eq!(MIN_DISTANCE.load(Ordering::Relaxed), 2000);
        begin_input();
        assert_eq!(MIN_DISTANCE.load(Ordering::Relaxed), u64::MAX);
    }
}
