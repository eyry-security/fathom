//! DNS brute-force mode for the shared engine.
//!
//! `DnsTarget` turns one word into `<word>.<domain>` and resolves the
//! configured record types through hickory-dns. It implements the core
//! [`Target`] trait. DNS mode deliberately mirrors the aiodnsbrute/c-ares
//! model: every record-type lookup gets its own short timeout and bounded
//! per-type retries, while the engine only supplies the closed concurrency
//! window and an overall backstop timeout.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use futures::future::join_all;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::calibration::Calibration;
use crate::engine::{Engine, Target};
use crate::matcher::Selector;
use crate::output::Event;
use crate::types::{EngineError, ExecResult, Response};
use crate::wordlist::WordSet;

/// Stable identity of one answer. TTL is deliberately excluded: a wildcard
/// record whose TTL changes between probes is still the same answer.
pub type AnswerKey = (String, String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsAnswer {
    #[serde(rename = "type")]
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

impl DnsAnswer {
    pub fn key(&self) -> AnswerKey {
        (self.record_type.clone(), self.value.clone())
    }
}

/// Per-record-type lookup accounting for one candidate.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DnsTypeStats {
    #[serde(rename = "type")]
    pub record_type: String,
    pub attempts: u64,
    pub timeouts: u64,
    pub incomplete: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
}

/// Aggregate per-record-type totals for a whole DNS run.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DnsTypeTotals {
    pub attempts: u64,
    pub timeouts: u64,
    pub incomplete: u64,
}

/// DNS-only additions to the JSONL stats trailer.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DnsRunStats {
    #[serde(default)]
    pub per_type: BTreeMap<String, DnsTypeTotals>,
    #[serde(default)]
    pub rcodes: BTreeMap<String, u64>,
}

impl DnsRunStats {
    pub fn merge(&mut self, other: &DnsRunStats) {
        for (record_type, totals) in &other.per_type {
            let entry = self.per_type.entry(record_type.clone()).or_default();
            entry.attempts += totals.attempts;
            entry.timeouts += totals.timeouts;
            entry.incomplete += totals.incomplete;
        }
        for (rcode, count) in &other.rcodes {
            *self.rcodes.entry(rcode.clone()).or_insert(0) += count;
        }
    }
}

/// Payload carried under the `dns` key of a result event.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsPayload {
    pub host: String,
    pub domain: String,
    pub record_types: Vec<String>,
    pub rcode: String,
    pub wildcard: bool,
    pub answers: Vec<DnsAnswer>,
    #[serde(default)]
    pub type_stats: Vec<DnsTypeStats>,
    #[serde(default)]
    pub rcodes: BTreeMap<String, u64>,
    #[serde(default)]
    pub incomplete_types: Vec<String>,
}

impl DnsPayload {
    pub fn answer_keys(&self) -> impl Iterator<Item = AnswerKey> + '_ {
        self.answers.iter().map(DnsAnswer::key)
    }
}

pub fn default_record_types(cname: bool) -> Vec<RecordType> {
    let mut record_types = vec![RecordType::A, RecordType::AAAA];
    if cname {
        record_types.push(RecordType::CNAME);
    }
    record_types
}

/// Build all configured resolvers. An empty list uses the system resolver.
/// Each explicit entry becomes its own UDP resolver so the target can rotate
/// between them deterministically.
pub fn build_resolvers(specs: &[String]) -> Result<Vec<TokioAsyncResolver>, EngineError> {
    if specs.is_empty() {
        return Ok(vec![system_resolver()?]);
    }

    let mut resolvers = Vec::with_capacity(specs.len());
    for spec in specs {
        let address = parse_resolver(spec)?;
        let mut name_servers = NameServerConfigGroup::with_capacity(1);
        name_servers.push(NameServerConfig::new(address, Protocol::Udp));

        let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
        let mut options = ResolverOpts::default();
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.preserve_intermediates = false;
        options.use_hosts_file = false;
        resolvers.push(TokioAsyncResolver::tokio(config, options));
    }
    Ok(resolvers)
}

fn system_resolver() -> Result<TokioAsyncResolver, EngineError> {
    TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|err| EngineError::non_retryable(format!("cannot read system resolver: {err}")))
}

fn parse_resolver(spec: &str) -> Result<SocketAddr, EngineError> {
    let spec = spec.trim();
    if let Ok(address) = SocketAddr::from_str(spec) {
        return Ok(address);
    }
    if let Ok(ip) = IpAddr::from_str(spec) {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(EngineError::non_retryable(format!(
        "invalid resolver `{spec}` (expected IP or IP:PORT)"
    )))
}

/// Union of answer identities returned by random non-existent names at the
/// level being brute-forced. A result is wildcard traffic when all of its
/// answer identities are present here (subset or equal).
#[derive(Debug, Clone, Default)]
pub struct WildcardSet {
    answers: HashSet<AnswerKey>,
}

impl WildcardSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.answers.len()
    }

    pub fn extend_answers<'a, I>(&mut self, answers: I)
    where
        I: IntoIterator<Item = &'a DnsAnswer>,
    {
        self.answers.extend(answers.into_iter().map(DnsAnswer::key));
    }

    pub fn contains(&self, answer: &DnsAnswer) -> bool {
        self.answers.contains(&answer.key())
    }

    /// True when every answer identity is part of the wildcard set. TTLs are
    /// ignored, and a result with an extra/distinct record is not a match.
    pub fn matches(&self, answers: &[DnsAnswer]) -> bool {
        !self.answers.is_empty()
            && !answers.is_empty()
            && answers.iter().all(|answer| self.contains(answer))
    }

    pub fn answers(&self) -> &HashSet<AnswerKey> {
        &self.answers
    }
}

const DEFAULT_PER_TYPE_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_PER_TYPE_RETRIES: u32 = 2;

pub struct DnsTarget {
    resolvers: Vec<TokioAsyncResolver>,
    next_resolver: AtomicUsize,
    domain: String,
    record_types: Vec<RecordType>,
    per_type_timeout: Duration,
    per_type_retries: u32,
    cancel_siblings: bool,
    totals: Mutex<DnsRunStats>,
    wildcards: RwLock<WildcardSet>,
    show_wildcards: bool,
}

impl DnsTarget {
    pub fn new(
        resolvers: Vec<TokioAsyncResolver>,
        domain: impl Into<String>,
        record_types: Vec<RecordType>,
    ) -> Self {
        assert!(!resolvers.is_empty(), "at least one resolver is required");
        Self {
            resolvers,
            next_resolver: AtomicUsize::new(0),
            domain: domain.into().trim_end_matches('.').to_string(),
            record_types,
            per_type_timeout: DEFAULT_PER_TYPE_TIMEOUT,
            per_type_retries: DEFAULT_PER_TYPE_RETRIES,
            cancel_siblings: true,
            totals: Mutex::new(DnsRunStats::default()),
            wildcards: RwLock::new(WildcardSet::default()),
            show_wildcards: false,
        }
    }

    pub fn with_per_type_timeout(mut self, timeout: Duration) -> Self {
        self.per_type_timeout = timeout;
        self
    }

    pub fn with_per_type_retries(mut self, retries: u32) -> Self {
        self.per_type_retries = retries;
        self
    }

    /// Controls whether an authoritative NXDOMAIN cancels sibling lookups.
    /// Disabled for wildcard probes so their in-flight queries drain before
    /// the main run starts.
    pub fn set_cancel_siblings(&mut self, cancel: bool) {
        self.cancel_siblings = cancel;
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn record_types(&self) -> &[RecordType] {
        &self.record_types
    }

    pub fn dns_stats(&self) -> DnsRunStats {
        self.totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn reset_dns_stats(&self) {
        *self
            .totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = DnsRunStats::default();
    }

    pub fn set_show_wildcards(&mut self, show: bool) {
        self.show_wildcards = show;
    }

    pub fn show_wildcards(&self) -> bool {
        self.show_wildcards
    }

    pub fn set_wildcards(&self, wildcards: WildcardSet) {
        *self
            .wildcards
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = wildcards;
    }

    pub fn wildcards(&self) -> WildcardSet {
        self.wildcards
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Probe random non-existent names at `<random>.<domain>` (the level being
    /// brute-forced) and union every answer they return. Probes use the same
    /// engine scheduler and rate caps as the main run but are not counted in
    /// its statistics.
    pub async fn detect_wildcards(&self, engine: &Engine, probes: usize) -> WildcardSet {
        let mut wildcards = WildcardSet::new();
        if probes == 0 {
            return wildcards;
        }

        let probe_words = (0..probes).map(|_| Ok(WordSet::single(random_label())));
        let _ = engine
            .run(
                probe_words,
                self,
                &Selector::default(),
                &Calibration::default(),
                |event| {
                    if let Event::Result { info, .. } = &event {
                        if let Some(payload) = payload_from_info(info) {
                            wildcards.extend_answers(payload.answers.iter());
                        }
                    }
                },
            )
            .await;
        wildcards
    }

    fn resolver(&self) -> &TokioAsyncResolver {
        let index = self.next_resolver.fetch_add(1, Ordering::Relaxed) % self.resolvers.len();
        &self.resolvers[index]
    }

    fn host(&self, words: &WordSet) -> String {
        let label = words.first.trim_end_matches('.');
        format!("{label}.{}", self.domain)
    }

    /// Resolve one record type with c-ares-like semantics: a short per-try
    /// timeout, bounded retries, rotated resolvers, and a final outcome that
    /// distinguishes negatives (NXDOMAIN/NODATA) from incomplete failures.
    async fn lookup_type(
        &self,
        name: Name,
        record_type: RecordType,
        sibling_decisive: &AtomicBool,
        mut nxdomain: tokio::sync::watch::Receiver<bool>,
        nxdomain_tx: tokio::sync::watch::Sender<bool>,
    ) -> TypeOutcome {
        let max_attempts = u64::from(self.per_type_retries).saturating_add(1);
        let mut attempts = 0u64;
        let mut timeouts = 0u64;
        let mut last_rcode = None;
        let mut last_error = None;

        for _ in 0..max_attempts {
            if self.cancel_siblings && *nxdomain.borrow() {
                // A sibling already proved NXDOMAIN before this lookup began;
                // do not send a query or count an attempt for it.
                return TypeOutcome {
                    record_type,
                    attempts,
                    timeouts,
                    answers: Vec::new(),
                    rcode: None,
                    negative: true,
                    incomplete: false,
                    error: None,
                };
            }
            attempts += 1;
            let resolver = self.resolver().clone();
            let lookup = resolver.lookup(name.clone(), record_type);
            let timed = tokio::time::timeout(self.per_type_timeout, lookup);
            tokio::pin!(timed);

            let result = if self.cancel_siblings {
                let Some(result) = (tokio::select! {
                    result = &mut timed => Some(result),
                    _ = nxdomain.changed() => None,
                }) else {
                    // A sibling query proved the name is NXDOMAIN, so this
                    // type cannot have data. Do not spend the rest of its 2s
                    // window.
                    return TypeOutcome {
                        record_type,
                        attempts,
                        timeouts,
                        answers: Vec::new(),
                        rcode: Some(ResponseCode::NXDomain),
                        negative: true,
                        incomplete: false,
                        error: None,
                    };
                };
                result
            } else {
                timed.await
            };

            match result {
                Err(_) => {
                    timeouts += 1;
                    last_error = Some(EngineError::timeout());
                    // Another type already produced a decisive answer or
                    // NXDOMAIN: keep this timeout as incomplete rather than
                    // spending more 2s tries on a name that is already known.
                    if sibling_decisive.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Ok(Ok(lookup)) => {
                    sibling_decisive.store(true, Ordering::Relaxed);
                    let mut answers = Vec::new();
                    for record in lookup.record_iter() {
                        let Some(data) = record.data() else {
                            continue;
                        };
                        let Some(value) = rdata_value(data) else {
                            continue;
                        };
                        answers.push(DnsAnswer {
                            record_type: record.record_type().to_string(),
                            value,
                            ttl: record.ttl(),
                        });
                    }
                    return TypeOutcome {
                        record_type,
                        attempts,
                        timeouts,
                        answers,
                        rcode: Some(ResponseCode::NoError),
                        negative: false,
                        incomplete: false,
                        error: None,
                    };
                }
                Ok(Err(error)) => match error.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                        let code = *response_code;
                        last_rcode = Some(code);
                        match code {
                            // NXDOMAIN and NOERROR/NODATA are ordinary negatives.
                            ResponseCode::NXDomain | ResponseCode::NoError => {
                                if code == ResponseCode::NXDomain {
                                    sibling_decisive.store(true, Ordering::Relaxed);
                                    let _ = nxdomain_tx.send(true);
                                }
                                return TypeOutcome {
                                    record_type,
                                    attempts,
                                    timeouts,
                                    answers: Vec::new(),
                                    rcode: Some(code),
                                    negative: true,
                                    incomplete: false,
                                    error: None,
                                };
                            }
                            // SERVFAIL/REFUSED are retryable resolver failures.
                            ResponseCode::ServFail | ResponseCode::Refused
                                if attempts < max_attempts =>
                            {
                                last_error = Some(EngineError::retryable(format!(
                                    "DNS {} for {}",
                                    rcode_label(code),
                                    name
                                )));
                            }
                            _ => {
                                last_error = Some(EngineError::non_retryable(format!(
                                    "DNS {} for {}",
                                    rcode_label(code),
                                    name
                                )));
                                break;
                            }
                        }
                    }
                    ResolveErrorKind::Timeout => {
                        timeouts += 1;
                        last_error = Some(EngineError::timeout());
                    }
                    ResolveErrorKind::Io(_) | ResolveErrorKind::NoConnections => {
                        last_error = Some(EngineError::retryable(error.to_string()));
                    }
                    _ => {
                        last_error = Some(EngineError::non_retryable(error.to_string()));
                        break;
                    }
                },
            }
        }

        TypeOutcome {
            record_type,
            attempts,
            timeouts,
            answers: Vec::new(),
            rcode: last_rcode,
            negative: false,
            incomplete: true,
            error: last_error,
        }
    }

    fn record_totals(&self, type_stats: &[DnsTypeStats], rcodes: &BTreeMap<String, u64>) {
        let mut totals = self
            .totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stat in type_stats {
            let entry = totals.per_type.entry(stat.record_type.clone()).or_default();
            entry.attempts += stat.attempts;
            entry.timeouts += stat.timeouts;
            entry.incomplete += stat.incomplete;
        }
        for (rcode, count) in rcodes {
            *totals.rcodes.entry(rcode.clone()).or_insert(0) += count;
        }
    }
}

struct TypeOutcome {
    record_type: RecordType,
    attempts: u64,
    timeouts: u64,
    answers: Vec<DnsAnswer>,
    rcode: Option<ResponseCode>,
    negative: bool,
    incomplete: bool,
    error: Option<EngineError>,
}

impl Target for DnsTarget {
    async fn execute(&self, words: &WordSet) -> Result<ExecResult, EngineError> {
        let host = self.host(words);
        let name = Name::from_ascii(format!("{host}.")).map_err(|err| {
            EngineError::non_retryable(format!("invalid DNS name `{host}`: {err}"))
        })?;
        let started = Instant::now();
        let sibling_decisive = AtomicBool::new(false);
        let (nxdomain_tx, nxdomain_rx) = tokio::sync::watch::channel(false);

        // Give the first type (A by default) a short head start. A fast
        // NXDOMAIN then cancels the remaining types before they add load,
        // while slow names still query every configured record type.
        let lookups = self
            .record_types
            .iter()
            .copied()
            .enumerate()
            .map(|(index, record_type)| {
                let name = name.clone();
                let sibling_decisive = &sibling_decisive;
                let nxdomain = nxdomain_rx.clone();
                let nxdomain_tx = nxdomain_tx.clone();
                async move {
                    if index > 0 {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                    self.lookup_type(name, record_type, sibling_decisive, nxdomain, nxdomain_tx)
                        .await
                }
            });
        let outcomes = join_all(lookups).await;

        let mut answers = Vec::new();
        let mut saw_answer = false;
        let mut saw_nxdomain = false;
        let mut any_definitive = false;
        let mut type_stats = Vec::with_capacity(outcomes.len());
        let mut rcodes = BTreeMap::new();
        let mut incomplete_types = Vec::new();
        let mut final_error = None;

        for outcome in outcomes {
            if let Some(code) = outcome.rcode {
                *rcodes.entry(rcode_label(code).to_string()).or_insert(0) += 1;
            }
            if outcome.negative {
                any_definitive = true;
                if outcome.rcode == Some(ResponseCode::NXDomain) {
                    saw_nxdomain = true;
                }
            }
            if !outcome.answers.is_empty() {
                any_definitive = true;
                saw_answer = true;
                answers.extend(outcome.answers.iter().cloned());
            }
            if outcome.incomplete {
                incomplete_types.push(outcome.record_type.to_string());
                if final_error.is_none() {
                    final_error = outcome.error;
                }
            }
            type_stats.push(DnsTypeStats {
                record_type: outcome.record_type.to_string(),
                attempts: outcome.attempts,
                timeouts: outcome.timeouts,
                incomplete: u64::from(outcome.incomplete),
                rcode: outcome.rcode.map(|code| rcode_label(code).to_string()),
            });
        }
        let elapsed = started.elapsed();

        self.record_totals(&type_stats, &rcodes);

        // If every record type failed (timeouts or retryable resolver errors)
        // this candidate is a genuine error, not an empty answer.
        if !any_definitive {
            return Err(final_error.unwrap_or_else(|| {
                EngineError::retryable(format!("all DNS lookups failed for {host}"))
            }));
        }

        let rcode = if saw_answer {
            ResponseCode::NoError
        } else if saw_nxdomain {
            ResponseCode::NXDomain
        } else {
            ResponseCode::NoError
        };

        answers.sort_by(|a, b| {
            a.record_type
                .cmp(&b.record_type)
                .then_with(|| a.value.cmp(&b.value))
        });
        answers.dedup();

        let body = answers
            .iter()
            .map(|answer| format!("{} {} {}", answer.record_type, answer.value, answer.ttl))
            .collect::<Vec<_>>()
            .join("\n");
        let wildcard = self
            .wildcards
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .matches(&answers);
        let payload = DnsPayload {
            host,
            domain: self.domain.clone(),
            record_types: self.record_types.iter().map(ToString::to_string).collect(),
            rcode: rcode_label(rcode).to_string(),
            wildcard,
            answers,
            type_stats,
            rcodes,
            incomplete_types,
        };

        // Retire the completed lookups before this candidate releases its
        // window slot, so the next candidate cannot be admitted while the
        // resolver is still accounting for this one.
        tokio::time::sleep(Duration::from_millis(5)).await;

        Ok(ExecResult {
            response: Response::from_body(u16::from(rcode), body, elapsed),
            info: json!({ "dns": payload }),
        })
    }

    fn keep_result(&self, _words: &WordSet, result: &ExecResult) -> bool {
        let Some(payload) = payload_from_info(&result.info) else {
            return true;
        };
        if payload.answers.is_empty() {
            return false;
        }
        if self.show_wildcards {
            return true;
        }
        !self
            .wildcards
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .matches(&payload.answers)
    }
}

fn random_label() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..18)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

fn rdata_value(data: &RData) -> Option<String> {
    match data {
        RData::A(address) => Some(address.0.to_string()),
        RData::AAAA(address) => Some(address.0.to_string()),
        RData::CNAME(name) => Some(
            name.0
                .to_string()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
        ),
        _ => None,
    }
}

fn rcode_label(rcode: ResponseCode) -> &'static str {
    match rcode {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        _ => "OTHER",
    }
}

pub fn payload_from_info(info: &serde_json::Value) -> Option<DnsPayload> {
    info.get("dns")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

/// Translate a discovered host into one line of Vedette input: a bare host, or
/// `host:port` when a port is supplied.
pub fn handoff_line(host: &str, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// Write one Vedette-compatible host line (including the trailing newline).
pub fn write_handoff_line<W: std::io::Write>(
    writer: &mut W,
    host: &str,
    port: Option<u16>,
) -> std::io::Result<()> {
    writeln!(writer, "{}", handoff_line(host, port))
}
