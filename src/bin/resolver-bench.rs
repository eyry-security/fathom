//! resolver-bench — vet DNS resolvers for the Eyry trio.
//!
//! Given probe domains and a truth file, this binary checks each resolver for
//! wrong/invented answers, measures A-query latency at low concurrency, then
//! drives a sustained burst at Fathom-like concurrency and reports the error
//! rate overall and over time buckets.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RecordType};
use rand::Rng;
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const DEFAULT_DOMAINS: &str = "example.com,eyry.io";
const DEFAULT_CONCURRENCY: usize = 256;
const DEFAULT_BURST: usize = 2000;
const DEFAULT_QUERIES: usize = 50;
const DEFAULT_TIMEOUT: &str = "1s";
const LATENCY_CONCURRENCY: usize = 2;
const NONEXISTENT_PER_DOMAIN: usize = 3;
const BURST_LABELS_PER_DOMAIN: usize = 16;
const BUCKET_COUNT: usize = 10;
const FAIL_ERROR_RATE: f64 = 0.05;
const DEGRADATION_GROWTH: f64 = 0.02;
const DEGRADATION_MIN_LATE: f64 = 0.01;

/// Named operator defaults. Every entry keeps its operator name so reports
/// never contain an anonymous resolver.
const DEFAULT_RESOLVERS: &[(&str, &str)] = &[
    ("Cloudflare", "1.1.1.1"),
    ("Cloudflare", "1.0.0.1"),
    ("Google", "8.8.8.8"),
    ("Google", "8.8.4.4"),
    ("Quad9", "9.9.9.9"),
    ("Verisign", "64.6.64.6"),
    ("OpenDNS", "208.67.222.222"),
    ("OpenDNS", "208.67.220.220"),
    ("Yandex", "195.46.39.40"),
    ("Yandex", "195.46.39.39"),
];

#[derive(Parser)]
#[command(
    name = "resolver-bench",
    version,
    about = "Vet DNS resolvers for correctness, latency, and load resilience"
)]
struct Cli {
    /// Probe domains (comma-separated or repeated).
    #[arg(long, value_delimiter = ',', default_value = DEFAULT_DOMAINS)]
    domains: Vec<String>,

    /// Truth file with one host per line that must resolve.
    #[arg(long, value_name = "FILE")]
    truth: PathBuf,

    /// Resolver override file with `name,ip` lines.
    #[arg(long, value_name = "FILE")]
    resolvers: Option<PathBuf>,

    /// Burst concurrency (Fathom-like closed window).
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Total queries in each resolver's sustained burst.
    #[arg(long, default_value_t = DEFAULT_BURST)]
    burst: usize,

    /// A queries per resolver for the latency sample.
    #[arg(long, default_value_t = DEFAULT_QUERIES)]
    queries: usize,

    /// Per-query DNS timeout, e.g. 1s or 500ms.
    #[arg(long, default_value = DEFAULT_TIMEOUT, value_parser = parse_duration)]
    timeout: Duration,

    /// Write the complete per-resolver metrics as JSON.
    #[arg(long, value_name = "OUT")]
    json: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolverSpec {
    name: String,
    address: SocketAddr,
}

impl ResolverSpec {
    fn endpoint(&self) -> String {
        if self.address.port() == 53 {
            self.address.ip().to_string()
        } else {
            self.address.to_string()
        }
    }
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct ProbeOutcome {
    answered: bool,
    negative: bool,
    /// Stable failure label (timeout, servfail, refused, io, ...).
    error: Option<String>,
    rcode: Option<String>,
}

impl ProbeOutcome {
    fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

#[derive(Debug, Clone, Default)]
struct ProbeRecord {
    latency: Duration,
    outcome: ProbeOutcome,
}

#[derive(Debug, Clone)]
struct TimedProbe {
    started: Duration,
    record: ProbeRecord,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct Correctness {
    pub truth_total: u64,
    pub truth_resolved: u64,
    pub truth_missing: u64,
    pub nonexistent_total: u64,
    pub nonexistent_answered: u64,
    pub wrong_answers: u64,
    pub wildcard: bool,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct LatencyStats {
    pub samples: u64,
    pub median_ms: f64,
    pub p95_ms: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Bucket {
    pub index: usize,
    pub start_ms: f64,
    pub end_ms: f64,
    pub attempts: u64,
    pub errors: u64,
    pub error_rate: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BurstStats {
    pub total: u64,
    pub errors: u64,
    pub error_rate: f64,
    pub elapsed_ms: f64,
    pub buckets: Vec<Bucket>,
    pub errors_by_kind: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverReport {
    pub rank: usize,
    pub name: String,
    pub resolver: String,
    pub correctness: Correctness,
    pub latency: LatencyStats,
    pub burst: BurstStats,
    pub degraded: bool,
    pub verdict: String,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    domains: &'a [String],
    truth_hosts: usize,
    nonexistent_probes: usize,
    concurrency: usize,
    burst: usize,
    queries: usize,
    timeout_ms: f64,
    resolvers: &'a [ResolverReport],
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    if cli.burst == 0 {
        bail!("--burst must be at least 1");
    }
    if cli.queries == 0 {
        bail!("--queries must be at least 1");
    }
    if cli.timeout.is_zero() {
        bail!("--timeout must be greater than 0");
    }

    let domains = normalize_domains(&cli.domains)?;
    if domains.is_empty() {
        bail!("--domains cannot be empty");
    }

    let truth_text = fs::read_to_string(&cli.truth)
        .with_context(|| format!("cannot read truth file {}", cli.truth.display()))?;
    let truth = parse_truth(&truth_text)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("invalid truth file {}", cli.truth.display()))?;

    let resolver_specs = match &cli.resolvers {
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("cannot read resolver file {}", path.display()))?;
            parse_resolvers(&text)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("invalid resolver file {}", path.display()))?
        }
        None => default_resolvers(),
    };

    let truth_set: HashSet<String> = truth.iter().cloned().collect();
    let nonexistent = generate_nonexistent(&domains, &truth_set, NONEXISTENT_PER_DOMAIN);
    let latency_targets = latency_targets(&truth, &domains);
    let burst_targets = burst_hosts(&domains, &truth, cli.burst);

    let mut reports = Vec::with_capacity(resolver_specs.len());
    for spec in &resolver_specs {
        eprintln!(
            "benchmarking {} ({}) against {}",
            spec.name,
            spec.endpoint(),
            domains.join(",")
        );
        let resolver = build_resolver(spec, cli.timeout)?;

        let mut truth_answered = Vec::with_capacity(truth.len());
        for host in &truth {
            let record = probe_a(&resolver, host, cli.timeout).await;
            truth_answered.push(record.outcome.answered);
        }
        let mut nonexistent_answered = Vec::with_capacity(nonexistent.len());
        for host in &nonexistent {
            let record = probe_a(&resolver, host, cli.timeout).await;
            nonexistent_answered.push(record.outcome.answered);
        }
        let correctness = score_correctness(&truth_answered, &nonexistent_answered);

        let latency = measure_latency(&resolver, &latency_targets, cli.queries, cli.timeout).await;
        let burst = run_burst(&resolver, &burst_targets, cli.concurrency, cli.timeout).await;
        let degraded = errors_degraded(&burst.buckets);
        let verdict = verdict_for(&correctness, burst.error_rate, degraded);

        reports.push(ResolverReport {
            rank: 0,
            name: spec.name.clone(),
            resolver: spec.endpoint(),
            correctness,
            latency,
            burst,
            degraded,
            verdict: verdict.to_string(),
        });
    }

    rank_reports(&mut reports);
    print_table(&reports);

    if let Some(path) = &cli.json {
        write_json(
            path,
            &JsonReport {
                domains: &domains,
                truth_hosts: truth.len(),
                nonexistent_probes: nonexistent.len(),
                concurrency: cli.concurrency,
                burst: cli.burst,
                queries: cli.queries,
                timeout_ms: cli.timeout.as_secs_f64() * 1000.0,
                resolvers: &reports,
            },
        )?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

fn build_resolver(spec: &ResolverSpec, timeout: Duration) -> Result<TokioAsyncResolver> {
    let mut name_servers = NameServerConfigGroup::with_capacity(1);
    name_servers.push(NameServerConfig::new(spec.address, Protocol::Udp));

    let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = timeout;
    options.num_concurrent_reqs = 1;
    options.cache_size = 0;
    options.use_hosts_file = false;
    options.preserve_intermediates = false;
    options.try_tcp_on_error = false;

    Ok(TokioAsyncResolver::tokio(config, options))
}

async fn probe_a(resolver: &TokioAsyncResolver, host: &str, timeout: Duration) -> ProbeRecord {
    let started = Instant::now();
    let Some(name) = Name::from_ascii(format!("{}.", host.trim_end_matches('.'))).ok() else {
        return ProbeRecord {
            latency: Duration::ZERO,
            outcome: ProbeOutcome {
                error: Some("invalid_name".to_string()),
                ..ProbeOutcome::default()
            },
        };
    };

    let deadline = timeout.saturating_add(Duration::from_millis(50));
    let result = tokio::time::timeout(deadline, resolver.lookup(name, RecordType::A)).await;
    let latency = started.elapsed();

    let outcome = match result {
        Err(_) => ProbeOutcome {
            error: Some("timeout".to_string()),
            ..ProbeOutcome::default()
        },
        Ok(Ok(lookup)) => {
            let answered = lookup.record_iter().next().is_some();
            ProbeOutcome {
                answered,
                negative: !answered,
                rcode: Some("NOERROR".to_string()),
                ..ProbeOutcome::default()
            }
        }
        Ok(Err(error)) => match error.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                let code = *response_code;
                let label = response_code_label(code);
                match code {
                    ResponseCode::NXDomain | ResponseCode::NoError => ProbeOutcome {
                        negative: true,
                        rcode: Some(label.to_string()),
                        ..ProbeOutcome::default()
                    },
                    _ => ProbeOutcome {
                        error: Some(label.to_ascii_lowercase()),
                        rcode: Some(label.to_string()),
                        ..ProbeOutcome::default()
                    },
                }
            }
            ResolveErrorKind::Timeout => ProbeOutcome {
                error: Some("timeout".to_string()),
                ..ProbeOutcome::default()
            },
            ResolveErrorKind::Io(_) => ProbeOutcome {
                error: Some("io".to_string()),
                ..ProbeOutcome::default()
            },
            ResolveErrorKind::NoConnections => ProbeOutcome {
                error: Some("no_connections".to_string()),
                ..ProbeOutcome::default()
            },
            _ => ProbeOutcome {
                error: Some("other".to_string()),
                ..ProbeOutcome::default()
            },
        },
    };

    ProbeRecord { latency, outcome }
}

async fn run_probes(
    resolver: &TokioAsyncResolver,
    hosts: &[String],
    concurrency: usize,
    timeout: Duration,
) -> Vec<TimedProbe> {
    if hosts.is_empty() {
        return Vec::new();
    }

    let start = Instant::now();
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for (index, host) in hosts.iter().cloned().enumerate() {
        let semaphore = semaphore.clone();
        let resolver = resolver.clone();
        tasks.spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return (index, Duration::ZERO, ProbeRecord::default());
            };
            let started = start.elapsed();
            let record = probe_a(&resolver, &host, timeout).await;
            (index, started, record)
        });
    }

    let mut results = Vec::with_capacity(hosts.len());
    while let Some(joined) = tasks.join_next().await {
        if let Ok(result) = joined {
            results.push(result);
        }
    }
    results.sort_by_key(|(index, _, _)| *index);
    results
        .into_iter()
        .map(|(_, started, record)| TimedProbe { started, record })
        .collect()
}

async fn measure_latency(
    resolver: &TokioAsyncResolver,
    targets: &[String],
    queries: usize,
    timeout: Duration,
) -> LatencyStats {
    if targets.is_empty() || queries == 0 {
        return LatencyStats::default();
    }

    let hosts: Vec<String> = (0..queries)
        .map(|index| targets[index % targets.len()].clone())
        .collect();
    let probes = run_probes(resolver, &hosts, LATENCY_CONCURRENCY, timeout).await;
    let samples = probes
        .into_iter()
        .filter(|probe| !probe.record.outcome.is_error())
        .map(|probe| probe.record.latency)
        .collect();
    latency_stats(samples)
}

async fn run_burst(
    resolver: &TokioAsyncResolver,
    hosts: &[String],
    concurrency: usize,
    timeout: Duration,
) -> BurstStats {
    let start = Instant::now();
    let probes = run_probes(resolver, hosts, concurrency, timeout).await;
    let elapsed = start.elapsed();

    let mut errors = 0u64;
    let mut errors_by_kind = BTreeMap::new();
    let mut samples = Vec::with_capacity(probes.len());

    for probe in &probes {
        let is_error = probe.record.outcome.is_error();
        if is_error {
            errors += 1;
            let kind = probe
                .record
                .outcome
                .error
                .clone()
                .unwrap_or_else(|| "other".to_string());
            *errors_by_kind.entry(kind).or_insert(0) += 1;
        }
        samples.push((probe.started, is_error));
    }

    let total = probes.len() as u64;
    let error_rate = if total == 0 {
        0.0
    } else {
        errors as f64 / total as f64
    };

    BurstStats {
        total,
        errors,
        error_rate,
        elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        buckets: bucketize(&samples, BUCKET_COUNT),
        errors_by_kind,
    }
}

pub fn score_correctness(truth_answered: &[bool], nonexistent_answered: &[bool]) -> Correctness {
    let truth_total = truth_answered.len() as u64;
    let truth_resolved = truth_answered.iter().filter(|answered| **answered).count() as u64;
    let truth_missing = truth_total.saturating_sub(truth_resolved);
    let nonexistent_total = nonexistent_answered.len() as u64;
    let nonexistent_answered_count = nonexistent_answered
        .iter()
        .filter(|answered| **answered)
        .count() as u64;

    Correctness {
        truth_total,
        truth_resolved,
        truth_missing,
        nonexistent_total,
        nonexistent_answered: nonexistent_answered_count,
        wrong_answers: truth_missing + nonexistent_answered_count,
        wildcard: nonexistent_answered_count > 0,
    }
}

pub fn latency_stats(mut samples: Vec<Duration>) -> LatencyStats {
    samples.sort_unstable();
    let count = samples.len();
    if count == 0 {
        return LatencyStats::default();
    }

    let median_ms = if count % 2 == 1 {
        samples[count / 2].as_secs_f64() * 1000.0
    } else {
        (samples[count / 2 - 1].as_secs_f64() + samples[count / 2].as_secs_f64()) * 500.0
    };
    let p95_ms = samples[percentile_index(count, 0.95)].as_secs_f64() * 1000.0;

    LatencyStats {
        samples: count as u64,
        median_ms,
        p95_ms,
    }
}

fn percentile_index(count: usize, percentile: f64) -> usize {
    let rank = (percentile * count as f64).ceil() as usize;
    rank.saturating_sub(1).min(count.saturating_sub(1))
}

pub fn bucketize(samples: &[(Duration, bool)], bucket_count: usize) -> Vec<Bucket> {
    let count = bucket_count.max(1);
    let mut buckets: Vec<Bucket> = (0..count)
        .map(|index| Bucket {
            index,
            start_ms: 0.0,
            end_ms: 0.0,
            attempts: 0,
            errors: 0,
            error_rate: 0.0,
        })
        .collect();

    if samples.is_empty() {
        return buckets;
    }

    let span = samples
        .iter()
        .map(|(at, _)| *at)
        .max()
        .unwrap_or(Duration::ZERO);
    let span_nanos = span.as_nanos().max(1);

    for (at, is_error) in samples {
        let index = if span.is_zero() {
            0
        } else {
            ((at.as_nanos() * count as u128) / span_nanos).min((count - 1) as u128) as usize
        };
        let bucket = &mut buckets[index];
        bucket.attempts += 1;
        if *is_error {
            bucket.errors += 1;
        }
    }

    let span_ms = span.as_secs_f64() * 1000.0;
    let width = span_ms / count as f64;
    for bucket in &mut buckets {
        bucket.start_ms = bucket.index as f64 * width;
        bucket.end_ms = if bucket.index + 1 == count {
            span_ms
        } else {
            (bucket.index + 1) as f64 * width
        };
        bucket.error_rate = if bucket.attempts == 0 {
            0.0
        } else {
            bucket.errors as f64 / bucket.attempts as f64
        };
    }

    buckets
}

pub fn errors_degraded(buckets: &[Bucket]) -> bool {
    let non_empty: Vec<&Bucket> = buckets
        .iter()
        .filter(|bucket| bucket.attempts > 0)
        .collect();
    if non_empty.len() < 2 {
        return false;
    }

    let split = non_empty.len() / 2;
    let (early, late) = non_empty.split_at(split);
    let early_attempts: u64 = early.iter().map(|bucket| bucket.attempts).sum();
    let early_errors: u64 = early.iter().map(|bucket| bucket.errors).sum();
    let late_attempts: u64 = late.iter().map(|bucket| bucket.attempts).sum();
    let late_errors: u64 = late.iter().map(|bucket| bucket.errors).sum();
    if early_attempts == 0 || late_attempts == 0 {
        return false;
    }

    let early_rate = early_errors as f64 / early_attempts as f64;
    let late_rate = late_errors as f64 / late_attempts as f64;
    let max_late_rate = late
        .iter()
        .map(|bucket| bucket.error_rate)
        .fold(0.0, f64::max);

    late_rate > early_rate + DEGRADATION_GROWTH && max_late_rate >= DEGRADATION_MIN_LATE
}

pub fn verdict_for(
    correctness: &Correctness,
    burst_error_rate: f64,
    degraded: bool,
) -> &'static str {
    if correctness.wrong_answers > 0 || burst_error_rate > FAIL_ERROR_RATE {
        "FAIL"
    } else if degraded {
        "DEGRADED"
    } else {
        "PASS"
    }
}

pub fn rank_reports(reports: &mut [ResolverReport]) {
    reports.sort_by(|left, right| {
        left.correctness
            .wrong_answers
            .cmp(&right.correctness.wrong_answers)
            .then_with(|| left.burst.error_rate.total_cmp(&right.burst.error_rate))
            .then_with(|| left.latency.p95_ms.total_cmp(&right.latency.p95_ms))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.resolver.cmp(&right.resolver))
    });
    for (index, report) in reports.iter_mut().enumerate() {
        report.rank = index + 1;
    }
}

fn print_table(reports: &[ResolverReport]) {
    let header = format!(
        "{:<4} {:<12} {:<20} {:>6} {:>5} {:>10} {:>8} {:>9} {:>9}  {}",
        "RANK",
        "OPERATOR",
        "RESOLVER",
        "WRONG",
        "WILD",
        "BURST ERR",
        "ERRORS",
        "MED ms",
        "P95 ms",
        "VERDICT"
    );
    println!("{header}");
    println!("{}", "-".repeat(header.len().max(96)));
    for report in reports {
        println!(
            "{:<4} {:<12} {:<20} {:>6} {:>5} {:>9.2}% {:>8} {:>9.1} {:>9.1}  {}",
            report.rank,
            report.name,
            report.resolver,
            report.correctness.wrong_answers,
            if report.correctness.wildcard {
                "yes"
            } else {
                "no"
            },
            report.burst.error_rate * 100.0,
            format!("{}/{}", report.burst.errors, report.burst.total),
            report.latency.median_ms,
            report.latency.p95_ms,
            report.verdict
        );
    }

    println!();
    for report in reports {
        println!(
            "verdict: {} ({}) = {}",
            report.name, report.resolver, report.verdict
        );
    }

    for report in reports {
        if report.burst.errors == 0 && !report.degraded {
            continue;
        }
        let trend = report
            .burst
            .buckets
            .iter()
            .map(|bucket| format!("{:.1}", bucket.error_rate * 100.0))
            .collect::<Vec<_>>()
            .join(" ");
        println!("buckets {} ({}): {} %", report.name, report.resolver, trend);
    }
}

fn write_json(path: &Path, report: &JsonReport<'_>) -> Result<()> {
    let file = fs::File::create(path)
        .with_context(|| format!("cannot create JSON output {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, report)
        .with_context(|| format!("cannot write JSON output {}", path.display()))?;
    writer
        .flush()
        .with_context(|| format!("cannot flush JSON output {}", path.display()))?;
    Ok(())
}

fn default_resolvers() -> Vec<ResolverSpec> {
    DEFAULT_RESOLVERS
        .iter()
        .map(|(name, address)| ResolverSpec {
            name: (*name).to_string(),
            address: parse_resolver_address(address).expect("built-in resolver address is valid"),
        })
        .collect()
}

fn parse_resolvers(text: &str) -> Result<Vec<ResolverSpec>, String> {
    let mut resolvers = Vec::new();
    for (line_number, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, address)) = line.split_once(',') else {
            return Err(format!(
                "line {}: expected `name,ip`, got `{line}`",
                line_number + 1
            ));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(format!(
                "line {}: resolver name cannot be empty",
                line_number + 1
            ));
        }
        let address = parse_resolver_address(address.trim())
            .map_err(|error| format!("line {}: `{error}`", line_number + 1))?;
        resolvers.push(ResolverSpec {
            name: name.to_string(),
            address,
        });
    }

    if resolvers.is_empty() {
        return Err("resolver file contains no entries".to_string());
    }
    Ok(resolvers)
}

fn parse_resolver_address(spec: &str) -> Result<SocketAddr, String> {
    let spec = spec.trim();
    if let Ok(address) = SocketAddr::from_str(spec) {
        return Ok(address);
    }
    if let Ok(ip) = IpAddr::from_str(spec) {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!(
        "invalid resolver `{spec}` (expected IP or IP:PORT)"
    ))
}

pub fn parse_truth(text: &str) -> Result<Vec<String>, String> {
    let mut hosts = Vec::new();
    let mut seen = HashSet::new();
    for (line_number, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let host = normalize_hostname(line)
            .map_err(|error| format!("line {}: {error}", line_number + 1))?;
        if seen.insert(host.clone()) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

fn normalize_domains(values: &[String]) -> Result<Vec<String>> {
    let mut domains = Vec::new();
    let mut seen = HashSet::new();
    for value in values {
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let domain = normalize_hostname(part).map_err(anyhow::Error::msg)?;
            if seen.insert(domain.clone()) {
                domains.push(domain);
            }
        }
    }
    Ok(domains)
}

fn normalize_hostname(raw: &str) -> Result<String, String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if !is_valid_hostname(&host) {
        return Err(format!("invalid DNS host `{raw}`"));
    }
    Ok(host)
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn generate_nonexistent(
    domains: &[String],
    truth: &HashSet<String>,
    per_domain: usize,
) -> Vec<String> {
    let mut probes = Vec::new();
    let mut rng = rand::thread_rng();
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    for domain in domains {
        let mut added = 0;
        let mut attempts = 0;
        while added < per_domain && attempts < per_domain * 20 {
            attempts += 1;
            let label: String = (0..20)
                .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                .collect();
            let host = format!("nx{label}.{domain}");
            if truth.contains(&host) {
                continue;
            }
            probes.push(host);
            added += 1;
        }
    }
    probes
}

fn latency_targets(truth: &[String], domains: &[String]) -> Vec<String> {
    let mut targets = truth.to_vec();
    let mut seen: HashSet<String> = targets.iter().cloned().collect();
    for domain in domains {
        if seen.insert(domain.clone()) {
            targets.push(domain.clone());
        }
    }
    targets
}

pub fn burst_hosts(domains: &[String], truth: &[String], burst: usize) -> Vec<String> {
    if domains.is_empty() || burst == 0 {
        return Vec::new();
    }

    let per_domain: Vec<Vec<String>> = domains
        .iter()
        .map(|domain| {
            let mut labels = vec![domain.clone()];
            let suffix = format!(".{domain}");
            for host in truth {
                let host = host.to_ascii_lowercase();
                if host == *domain {
                    continue;
                }
                if let Some(prefix) = host.strip_suffix(&suffix) {
                    if !prefix.is_empty() {
                        labels.push(format!("{prefix}.{domain}"));
                    }
                }
            }
            labels.sort();
            labels.dedup();
            for index in 0..BURST_LABELS_PER_DOMAIN {
                let label = format!("bench-{index}.{domain}");
                if !labels.contains(&label) {
                    labels.push(label);
                }
            }
            labels
        })
        .collect();

    let mut hosts = Vec::with_capacity(burst);
    for index in 0..burst {
        let domain_index = index % domains.len();
        let labels = &per_domain[domain_index];
        hosts.push(labels[(index / domains.len()) % labels.len()].clone());
    }
    hosts
}

fn response_code_label(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        _ => "OTHER",
    }
}

pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("duration cannot be empty".to_string());
    }

    let (number, unit) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1e-3)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else {
        (value, 1.0)
    };

    let number: f64 = number
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration `{value}`"))?;
    if !number.is_finite() || number <= 0.0 {
        return Err(format!("duration must be greater than 0: `{value}`"));
    }

    Ok(Duration::from_secs_f64(number * unit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn report(name: &str, wrong: u64, error_rate: f64, p95_ms: f64) -> ResolverReport {
        ResolverReport {
            rank: 0,
            name: name.to_string(),
            resolver: format!("192.0.2.{}", wrong + 1),
            correctness: Correctness {
                wrong_answers: wrong,
                ..Correctness::default()
            },
            latency: LatencyStats {
                samples: 1,
                median_ms: p95_ms,
                p95_ms,
            },
            burst: BurstStats {
                error_rate,
                ..BurstStats::default()
            },
            degraded: false,
            verdict: "PASS".to_string(),
        }
    }

    #[test]
    fn truth_parser_ignores_comments_blank_lines_and_duplicates() {
        let text = "\n# comment\nwww.alpha.test\n\nwww.alpha.test.  # trailing\nmail.beta.test\n";
        let hosts = parse_truth(text).unwrap();
        assert_eq!(hosts, vec!["www.alpha.test", "mail.beta.test"]);
    }

    #[test]
    fn truth_parser_rejects_invalid_hosts() {
        assert!(parse_truth("bad host.test").is_err());
        assert!(parse_truth("-bad.test").is_err());
        assert!(parse_truth("a..b.test").is_err());
    }

    #[test]
    fn correctness_flags_missing_truth_and_invented_answers() {
        let correctness = score_correctness(&[true, true, false], &[false, true]);
        assert_eq!(correctness.truth_total, 3);
        assert_eq!(correctness.truth_resolved, 2);
        assert_eq!(correctness.truth_missing, 1);
        assert_eq!(correctness.nonexistent_total, 2);
        assert_eq!(correctness.nonexistent_answered, 1);
        assert_eq!(correctness.wrong_answers, 2);
        assert!(correctness.wildcard);
    }

    #[test]
    fn correctness_without_invented_answers_is_not_wildcard() {
        let correctness = score_correctness(&[true], &[false, false]);
        assert_eq!(correctness.wrong_answers, 0);
        assert!(!correctness.wildcard);
    }

    #[test]
    fn latency_uses_median_and_nearest_rank_p95() {
        let millis = |value: u64| Duration::from_millis(value);
        let small = latency_stats(vec![millis(10), millis(20), millis(30), millis(40)]);
        assert_eq!(small.samples, 4);
        assert_eq!(small.median_ms, 25.0);
        assert_eq!(small.p95_ms, 40.0);

        let large = latency_stats((1..=100).map(millis).collect());
        assert_eq!(large.median_ms, 50.5);
        assert_eq!(large.p95_ms, 95.0);
    }

    #[test]
    fn bucket_math_splits_attempts_and_errors_over_time() {
        let millis = |value: u64| Duration::from_millis(value);
        let samples = vec![
            (millis(0), false),
            (millis(100), false),
            (millis(200), true),
            (millis(300), false),
            (millis(400), true),
        ];
        let buckets = bucketize(&samples, 4);
        assert_eq!(buckets.len(), 4);
        assert_eq!(buckets[0].attempts, 1);
        assert_eq!(buckets[1].attempts, 1);
        assert_eq!(buckets[2].attempts, 1);
        assert_eq!(buckets[2].errors, 1);
        assert_eq!(buckets[3].attempts, 2);
        assert_eq!(buckets[3].errors, 1);
        assert_eq!(buckets.iter().map(|bucket| bucket.attempts).sum::<u64>(), 5);
        assert_eq!(buckets.iter().map(|bucket| bucket.errors).sum::<u64>(), 2);
        assert_eq!(buckets[2].error_rate, 1.0);
        assert_eq!(buckets[3].error_rate, 0.5);
        assert_eq!(buckets[3].end_ms, 400.0);
    }

    #[test]
    fn bucket_math_handles_zero_span() {
        let buckets = bucketize(&[(Duration::ZERO, true); 3], 5);
        assert_eq!(buckets[0].attempts, 3);
        assert_eq!(buckets[0].errors, 3);
        assert_eq!(buckets[0].error_rate, 1.0);
        assert!(buckets[1..].iter().all(|bucket| bucket.attempts == 0));
    }

    #[test]
    fn degradation_detects_only_late_error_growth() {
        let millis = |value: u64| Duration::from_millis(value);
        let mut samples = Vec::new();
        for index in 0..100u64 {
            samples.push((millis(index * 10), index >= 60));
        }
        let buckets = bucketize(&samples, 10);
        assert!(errors_degraded(&buckets));

        let early_errors: Vec<(Duration, bool)> = (0..100u64)
            .map(|index| (millis(index * 10), index < 40))
            .collect();
        let buckets = bucketize(&early_errors, 10);
        assert!(!errors_degraded(&buckets));
    }

    #[test]
    fn ranking_orders_by_wrong_then_error_rate_then_p95() {
        let mut reports = vec![
            report("wrong", 2, 0.0, 1.0),
            report("slow", 0, 0.01, 90.0),
            report("fast", 0, 0.01, 10.0),
            report("clean", 0, 0.0, 500.0),
        ];
        rank_reports(&mut reports);
        let order: Vec<&str> = reports.iter().map(|item| item.name.as_str()).collect();
        assert_eq!(order, vec!["clean", "fast", "slow", "wrong"]);
        assert_eq!(reports[0].rank, 1);
        assert_eq!(reports[3].rank, 4);
    }

    #[test]
    fn verdict_thresholds_match_the_spec() {
        let clean = Correctness::default();
        assert_eq!(verdict_for(&clean, 0.0, false), "PASS");
        assert_eq!(verdict_for(&clean, 0.02, true), "DEGRADED");
        assert_eq!(verdict_for(&clean, 0.02, false), "PASS");
        assert_eq!(verdict_for(&clean, 0.06, false), "FAIL");
        let wrong = Correctness {
            wrong_answers: 1,
            ..Correctness::default()
        };
        assert_eq!(verdict_for(&wrong, 0.0, false), "FAIL");
    }

    #[test]
    fn resolver_file_requires_names_and_parses_ports() {
        let resolvers =
            parse_resolvers("Alpha,192.0.2.1\n# comment\nBeta,192.0.2.2:5353\n").unwrap();
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].name, "Alpha");
        assert_eq!(resolvers[0].address.port(), 53);
        assert_eq!(resolvers[1].endpoint(), "192.0.2.2:5353");
        assert!(parse_resolvers(",192.0.2.1").is_err());
        assert!(parse_resolvers("Alpha,not-an-ip").is_err());
    }

    #[test]
    fn burst_hosts_split_evenly_across_probe_domains() {
        let domains = vec!["alpha.test".to_string(), "beta.test".to_string()];
        let truth = vec!["www.alpha.test".to_string()];
        let hosts = burst_hosts(&domains, &truth, 8);
        assert_eq!(hosts.len(), 8);
        let alpha = hosts
            .iter()
            .filter(|host| host.as_str() == "alpha.test" || host.ends_with(".alpha.test"))
            .count();
        let beta = hosts
            .iter()
            .filter(|host| host.as_str() == "beta.test" || host.ends_with(".beta.test"))
            .count();
        assert_eq!(alpha, 4);
        assert_eq!(beta, 4);
        assert!(hosts.iter().any(|host| host == "www.alpha.test"));
    }

    #[test]
    fn duration_parser_accepts_seconds_and_milliseconds() {
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("nope").is_err());
    }

    mod fixture {
        use std::collections::HashMap;
        use std::net::Ipv4Addr;
        use std::sync::Arc;

        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record, RecordType};
        use tokio::net::UdpSocket;

        pub async fn start(
            answers: Vec<(&'static str, Ipv4Addr)>,
        ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let address = socket.local_addr().unwrap();
            let answers: HashMap<String, Ipv4Addr> = answers
                .into_iter()
                .map(|(name, ip)| (name.trim_end_matches('.').to_ascii_lowercase(), ip))
                .collect();

            let handle = tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                        break;
                    };
                    let Ok(request) = Message::from_vec(&buffer[..length]) else {
                        continue;
                    };

                    let mut response = Message::new();
                    response.set_id(request.id());
                    response.set_message_type(MessageType::Response);
                    response.set_op_code(OpCode::Query);
                    response.set_recursion_desired(request.recursion_desired());
                    response.set_recursion_available(true);
                    response.set_authoritative(true);

                    let mut response_code = ResponseCode::NoError;
                    let mut records = Vec::new();
                    for query in request.queries() {
                        response.add_query(query.clone());
                        let key = query
                            .name()
                            .to_ascii()
                            .trim_end_matches('.')
                            .to_ascii_lowercase();
                        match answers.get(&key) {
                            Some(ip) if query.query_type() == RecordType::A => {
                                records.push(Record::from_rdata(
                                    query.name().clone(),
                                    60,
                                    RData::A(A(*ip)),
                                ));
                            }
                            Some(_) => {}
                            None => response_code = ResponseCode::NXDomain,
                        }
                    }

                    response.set_response_code(response_code);
                    for record in records {
                        response.add_answer(record);
                    }
                    if let Ok(bytes) = response.to_vec() {
                        let _ = socket.send_to(&bytes, peer).await;
                    }
                }
            });

            (address, handle)
        }
    }

    #[tokio::test]
    async fn hermetic_udp_round_trip_scores_and_bursts() {
        let (address, server) =
            fixture::start(vec![("known.fixture.test", Ipv4Addr::new(192, 0, 2, 10))]).await;
        let spec = ResolverSpec {
            name: "Fixture".to_string(),
            address,
        };
        let timeout = Duration::from_millis(500);
        let resolver = build_resolver(&spec, timeout).unwrap();

        let known = probe_a(&resolver, "known.fixture.test", timeout).await;
        assert!(known.outcome.answered);
        assert!(known.outcome.error.is_none());

        let missing = probe_a(&resolver, "missing.fixture.test", timeout).await;
        assert!(missing.outcome.negative);
        assert!(missing.outcome.error.is_none());

        let correctness = score_correctness(&[known.outcome.answered], &[missing.outcome.answered]);
        assert_eq!(correctness.wrong_answers, 0);
        assert!(!correctness.wildcard);

        let hosts = vec!["known.fixture.test".to_string(); 8];
        let burst = run_burst(&resolver, &hosts, 4, timeout).await;
        assert_eq!(burst.total, 8);
        assert_eq!(burst.errors, 0);
        assert_eq!(burst.error_rate, 0.0);
        assert_eq!(
            burst
                .buckets
                .iter()
                .map(|bucket| bucket.attempts)
                .sum::<u64>(),
            8
        );

        server.abort();
    }
}
