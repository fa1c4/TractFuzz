use std::{
    env,
    fs::{File, OpenOptions},
    io::Write,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Mutex, OnceLock,
    },
};

use libafl::prelude::{ExitKind, Named, Observer, UsesInput};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeaconMode {
    Off = 0,
    Shadow = 1,
    Hard = 2,
}

static MODE: AtomicU8 = AtomicU8::new(BeaconMode::Hard as u8);
static TOTAL_WOULD_PRUNE: AtomicU64 = AtomicU64::new(0);
static TOTAL_PRUNED: AtomicU64 = AtomicU64::new(0);
static INPUT_WOULD_PRUNE: AtomicU64 = AtomicU64::new(0);
static INPUT_PRUNED: AtomicU64 = AtomicU64::new(0);
static INPUT_ID: AtomicU64 = AtomicU64::new(0);
static TRACE: OnceLock<Option<Mutex<File>>> = OnceLock::new();
static MAGMA_RESET: OnceLock<Option<unsafe extern "C" fn()>> = OnceLock::new();

pub fn set_mode(mode: BeaconMode) {
    MODE.store(mode as u8, Ordering::Relaxed);
}

#[must_use]
pub fn totals() -> (u64, u64) {
    (
        TOTAL_WOULD_PRUNE.load(Ordering::Relaxed),
        TOTAL_PRUNED.load(Ordering::Relaxed),
    )
}

pub fn begin_input() {
    if let Some(reset) = MAGMA_RESET.get_or_init(|| {
        let name = b"__beacon_magma_reset\0";
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) };
        if symbol.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute(symbol) })
        }
    }) {
        unsafe { reset() };
    }
    INPUT_ID.fetch_add(1, Ordering::Relaxed);
    INPUT_WOULD_PRUNE.store(0, Ordering::Relaxed);
    INPUT_PRUNED.store(0, Ordering::Relaxed);
}

fn trace_decision(guard_id: u32, mode: u8, pruned: bool) {
    let trace = TRACE.get_or_init(|| {
        let path = env::var_os("BEACON_TRACE")?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        let mut file = file;
        if file.metadata().map(|m| m.len() == 0).unwrap_or(false) {
            let _ = writeln!(
                file,
                "input_id,guard_id,mode,decision,target_state,canary_state"
            );
        }
        Some(Mutex::new(file))
    });
    if let Some(trace) = trace {
        if let Ok(mut file) = trace.lock() {
            let mode_name = if mode == BeaconMode::Hard as u8 {
                "hard"
            } else {
                "shadow"
            };
            let decision = if pruned { "prune" } else { "continue" };
            // This hook is inserted before the first target instruction.
            let _ = writeln!(
                file,
                "{},{},{},{},not_executed,not_executed",
                INPUT_ID.load(Ordering::Relaxed),
                guard_id,
                mode_name,
                decision
            );
        }
    }
}

// Called only when a statically inferred entry precondition fails.
// The in-process runner is safe here because no target code has run yet.
#[no_mangle]
pub extern "C" fn __beacon_should_prune(guard_id: u32) -> bool {
    let mode = MODE.load(Ordering::Relaxed);
    if mode == BeaconMode::Off as u8 {
        return false;
    }
    TOTAL_WOULD_PRUNE.fetch_add(1, Ordering::Relaxed);
    INPUT_WOULD_PRUNE.fetch_add(1, Ordering::Relaxed);
    let pruned = mode == BeaconMode::Hard as u8;
    trace_decision(guard_id, mode, pruned);
    if pruned {
        TOTAL_PRUNED.fetch_add(1, Ordering::Relaxed);
        INPUT_PRUNED.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BeaconObserver {
    name: String,
    would_prune: u64,
    pruned: u64,
}

impl BeaconObserver {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            would_prune: 0,
            pruned: 0,
        }
    }

    #[must_use]
    pub fn counts(&self) -> (u64, u64) {
        (self.would_prune, self.pruned)
    }
}

impl Named for BeaconObserver {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<S: UsesInput> Observer<S> for BeaconObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), libafl::Error> {
        begin_input();
        self.would_prune = 0;
        self.pruned = 0;
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl::Error> {
        self.would_prune = INPUT_WOULD_PRUNE.load(Ordering::Relaxed);
        self.pruned = INPUT_PRUNED.load(Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_report_decision() {
        let path = env::temp_dir().join(format!("beacon-trace-test-{}.csv", std::process::id()));
        let _ = std::fs::remove_file(&path);
        env::set_var("BEACON_TRACE", &path);
        begin_input();
        set_mode(BeaconMode::Off);
        assert!(!__beacon_should_prune(1));
        set_mode(BeaconMode::Shadow);
        assert!(!__beacon_should_prune(1));
        assert_eq!(INPUT_WOULD_PRUNE.load(Ordering::Relaxed), 1);
        begin_input();
        assert_eq!(INPUT_WOULD_PRUNE.load(Ordering::Relaxed), 0);
        set_mode(BeaconMode::Hard);
        assert!(__beacon_should_prune(1));
        assert_eq!(INPUT_PRUNED.load(Ordering::Relaxed), 1);
        let trace = std::fs::read_to_string(&path).unwrap();
        assert!(trace.contains(",1,shadow,continue,not_executed,not_executed"));
        assert!(trace.contains(",1,hard,prune,not_executed,not_executed"));
        env::remove_var("BEACON_TRACE");
        std::fs::remove_file(path).unwrap();
    }
}
