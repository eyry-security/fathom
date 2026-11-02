//! Bounded repair sweep around the scheduler.
//!
//! The main pass records candidates whose lookups ended incomplete. This
//! module re-queries only those candidates, merges only confirmed answers, and
//! performs at most two passes so a bad resolver window cannot cause a loop.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::calibration::Calibration;
use crate::engine::{Engine, Target};
use crate::matcher::Selector;
use crate::output::Event;
use crate::types::{EngineError, ExecResult};
use crate::wordlist::WordSet;

pub const MAX_REPAIR_PASSES: usize = 2;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairSweepStats {
    pub subset: usize,
    pub attempts: u64,
    pub recovered: u64,
    pub passes: usize,
}

/// Re-query `pending` at the concurrency already configured on `engine`.
///
/// `is_incomplete` identifies candidates that need another pass. `host_of`
/// names a confirmed answer so duplicates and hosts already found by the main
/// pass are not emitted again. `emit` receives only kept, new confirmed
/// results; failed or empty sweep answers never reach the output.
pub async fn repair_sweep<T, K, H, C>(
    engine: &Engine,
    target: &T,
    pending: Vec<WordSet>,
    already_found: &HashSet<String>,
    mut is_incomplete: K,
    mut host_of: H,
    mut emit: C,
) -> Result<RepairSweepStats, EngineError>
where
    T: Target,
    K: FnMut(&WordSet, &Result<ExecResult, EngineError>) -> bool,
    H: FnMut(&ExecResult) -> Option<String>,
    C: FnMut(Event),
{
    let mut stats = RepairSweepStats {
        subset: pending.len(),
        ..RepairSweepStats::default()
    };
    let mut current = pending;
    let mut recovered_hosts = HashSet::new();

    for _ in 0..MAX_REPAIR_PASSES {
        if current.is_empty() {
            break;
        }
        stats.passes += 1;
        let mut remainder = Vec::new();
        let words = current.iter().cloned().map(Ok);

        let report = engine
            .run_observed(
                words,
                target,
                &Selector::default(),
                &Calibration::default(),
                |_| {},
                |words, result, kept| {
                    if is_incomplete(words, result) {
                        remainder.push(words.clone());
                    }
                    if !kept {
                        return;
                    }
                    let Ok(result) = result else {
                        return;
                    };
                    let Some(host) = host_of(result) else {
                        return;
                    };
                    if already_found.contains(&host) || !recovered_hosts.insert(host) {
                        return;
                    }
                    emit(Event::result(words, result));
                },
            )
            .await?;

        stats.attempts += report.stats.requests;
        current = remainder;
    }

    stats.recovered = recovered_hosts.len() as u64;
    Ok(stats)
}
