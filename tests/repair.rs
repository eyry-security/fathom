use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fathom::{
    Calibration, DnsRunStats, Engine, EngineConfig, EngineError, Event, ExecResult,
    RepairSweepStats, Response, RunReport, RunStats, Selector, Target, WordSet, repair_sweep,
    result_host, result_is_incomplete,
};

#[derive(Default)]
struct State {
    calls: HashMap<String, usize>,
    incomplete_calls: HashMap<String, usize>,
    stuck: HashSet<String>,
    confirmed: HashSet<String>,
}

#[derive(Clone)]
struct TestTarget {
    state: Arc<Mutex<State>>,
}

impl TestTarget {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    fn confirm(self, label: &str, incomplete_calls: usize) -> Self {
        let mut state = self.state.lock().unwrap();
        state.confirmed.insert(label.to_string());
        state
            .incomplete_calls
            .insert(label.to_string(), incomplete_calls);
        drop(state);
        self
    }

    fn stuck(self, label: &str) -> Self {
        self.state.lock().unwrap().stuck.insert(label.to_string());
        self
    }

    fn calls(&self) -> HashMap<String, usize> {
        self.state.lock().unwrap().calls.clone()
    }
}

impl Target for TestTarget {
    async fn execute(&self, words: &WordSet) -> Result<ExecResult, EngineError> {
        let label = words.first.clone();
        let host = format!("{label}.example.com");
        let mut state = self.state.lock().unwrap();
        let call = {
            let count = state.calls.entry(label.clone()).or_insert(0);
            *count += 1;
            *count
        };
        let threshold = state.incomplete_calls.get(&label).copied().unwrap_or(0);
        let incomplete = state.stuck.contains(&label) || call <= threshold;
        let confirmed = state.confirmed.contains(&label) && !incomplete;
        drop(state);

        if !confirmed {
            let info = if incomplete {
                serde_json::json!({ "fake_incomplete": true, "host": host })
            } else {
                serde_json::json!({ "host": host })
            };
            return Ok(ExecResult {
                response: Response::from_body(200, "", Duration::ZERO),
                info,
            });
        }

        Ok(ExecResult {
            response: Response::from_body(200, "A 192.0.2.1 60", Duration::ZERO),
            info: serde_json::json!({ "host": host }),
        })
    }

    fn keep_result(&self, _words: &WordSet, result: &ExecResult) -> bool {
        !result.response.body.is_empty()
    }
}

fn engine(concurrency: usize) -> Engine {
    Engine::new(EngineConfig {
        concurrency,
        rate_limit: None,
        timeout: Duration::from_secs(1),
        retries: 0,
        retry_base_delay: Duration::from_millis(1),
        circuit_breaker: None,
    })
}

fn words(labels: &[&str]) -> Vec<std::io::Result<WordSet>> {
    labels
        .iter()
        .map(|label| Ok(WordSet::single(*label)))
        .collect()
}

fn fake_incomplete(_words: &WordSet, result: &Result<ExecResult, EngineError>) -> bool {
    match result {
        Ok(result) => result
            .info
            .get("fake_incomplete")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        Err(_) => true,
    }
}

fn fake_host(result: &ExecResult) -> Option<String> {
    result
        .info
        .get("host")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn event_host(event: &Event) -> Option<String> {
    match event {
        Event::Result { info, .. } => info
            .get("host")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        Event::Stats { .. } => None,
    }
}

#[tokio::test]
async fn sweep_requeries_only_the_incomplete_subset() {
    let target = TestTarget::new()
        .confirm("complete", 0)
        .confirm("partial", 1)
        .stuck("stuck");
    let engine = engine(4);

    let mut pending = Vec::new();
    engine
        .run_observed(
            words(&["complete", "partial", "stuck", "negative"]).into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |_| {},
            |words, result, _| {
                if fake_incomplete(words, result) {
                    pending.push(words.first.clone());
                }
            },
        )
        .await
        .unwrap();

    pending.sort();
    assert_eq!(pending, vec!["partial", "stuck"]);

    let before = target.calls();
    let stats = repair_sweep(
        &engine,
        &target,
        vec![WordSet::single("stuck")],
        &HashSet::new(),
        fake_incomplete,
        |result| {
            result
                .info
                .get("host")
                .and_then(|host| host.as_str())
                .map(str::to_string)
        },
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(stats.subset, 1);
    assert_eq!(stats.attempts, 2);
    assert_eq!(stats.passes, 2);

    let after = target.calls();
    assert_eq!(after["stuck"], before["stuck"] + 2);
    assert_eq!(after["complete"], before["complete"]);
    assert_eq!(after["partial"], before["partial"]);
    assert_eq!(after["negative"], before["negative"]);
}

#[tokio::test]
async fn sweep_merges_only_confirmed_new_answers() {
    let target = TestTarget::new()
        .confirm("confirmed", 0)
        .confirm("already", 0)
        .stuck("unconfirmed");
    let mut already_found = HashSet::new();
    already_found.insert("already.example.com".to_string());

    let mut events = Vec::new();
    let stats = repair_sweep(
        &engine(4),
        &target,
        vec![
            WordSet::single("confirmed"),
            WordSet::single("unconfirmed"),
            WordSet::single("already"),
        ],
        &already_found,
        fake_incomplete,
        fake_host,
        |event| events.push(event),
    )
    .await
    .unwrap();

    let mut hosts: Vec<_> = events.iter().filter_map(event_host).collect();
    hosts.sort();
    assert_eq!(hosts, vec!["confirmed.example.com"]);
    assert_eq!(stats.recovered, 1);
}

#[tokio::test]
async fn sweep_stops_after_two_passes() {
    let target = TestTarget::new().stuck("stuck");

    let stats = repair_sweep(
        &engine(2),
        &target,
        vec![WordSet::single("stuck")],
        &HashSet::new(),
        fake_incomplete,
        fake_host,
        |_| {},
    )
    .await
    .unwrap();

    assert_eq!(stats.passes, 2);
    assert_eq!(stats.attempts, 2);
    assert_eq!(stats.recovered, 0);
    assert_eq!(target.calls()["stuck"], 2);
}

#[tokio::test]
async fn sweep_stats_report_recovered_hosts_across_passes() {
    let target = TestTarget::new()
        .confirm("early", 0)
        .confirm("late", 1)
        .stuck("never");

    let mut events = Vec::new();
    let stats = repair_sweep(
        &engine(4),
        &target,
        vec![
            WordSet::single("early"),
            WordSet::single("late"),
            WordSet::single("never"),
        ],
        &HashSet::new(),
        fake_incomplete,
        fake_host,
        |event| events.push(event),
    )
    .await
    .unwrap();

    let mut hosts: Vec<_> = events.iter().filter_map(event_host).collect();
    hosts.sort();
    assert_eq!(hosts, vec!["early.example.com", "late.example.com"]);
    assert_eq!(stats.subset, 3);
    assert_eq!(stats.passes, 2);
    assert_eq!(stats.attempts, 5);
    assert_eq!(stats.recovered, 2);
}

#[test]
fn result_helpers_reuse_dns_incomplete_signal() {
    let incomplete = ExecResult {
        response: Response::from_body(200, "A 192.0.2.1 60", Duration::ZERO),
        info: serde_json::json!({
            "dns": {
                "host": "partial.example.com",
                "domain": "example.com",
                "record_types": ["A", "AAAA"],
                "rcode": "NOERROR",
                "wildcard": false,
                "answers": [],
                "incomplete_types": ["AAAA"]
            }
        }),
    };
    assert!(result_is_incomplete(&Ok(incomplete.clone())));
    assert_eq!(
        result_host(&incomplete),
        Some("partial.example.com".to_string())
    );
    assert!(result_is_incomplete(&Err(EngineError::timeout())));
}

#[test]
fn stats_line_reports_sweep_recovery_count() {
    let mut dns = DnsRunStats::default();
    dns.sweep = Some(RepairSweepStats {
        subset: 3,
        attempts: 5,
        recovered: 2,
        passes: 2,
    });
    let event = Event::stats_with_dns(
        &RunReport {
            stats: RunStats::default(),
            elapsed: Duration::ZERO,
            rps: 0.0,
        },
        Some(dns),
    );
    let line = event.stats_line().unwrap();
    assert!(line.contains("sweep_subset=3"));
    assert!(line.contains("sweep_attempts=5"));
    assert!(line.contains("sweep_recovered=2"));
}
