use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use fathom::http_mode::recursion_base;
use fathom::{
    Calibration, CircuitBreakerConfig, Criteria, DnsTarget, Engine, EngineConfig, Event,
    HttpOptions, HttpTarget, HttpTemplate, HumanTable, JsonlWriter, Mode, RunReport, RunStats,
    Selector, TimeRange, WordlistSpec, build_client, build_resolvers, compile_regexes,
    default_record_types, expand_extensions, payload_from_info, write_handoff_line,
};

const DEFAULT_MATCH_STATUSES: &str = "200-299,301,302,307,401,403,405,500";

#[derive(Parser)]
#[command(
    name = "fathom",
    version,
    about = "Rust fuzzing engine for the Eyry suite (HTTP now, DNS next)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fuzz an HTTP template containing FUZZ / FUZZ2.
    Http(HttpArgs),
    /// Brute-force <word>.<domain> through DNS.
    Dns(DnsArgs),
}

#[derive(Args)]
struct HttpArgs {
    /// URL template; FUZZ / FUZZ2 may appear anywhere.
    #[arg(short = 'u', long = "url", value_name = "URL")]
    url: String,

    /// One wordlist, or two for FUZZ + FUZZ2.
    #[arg(
        short = 'w',
        long = "wordlist",
        value_name = "FILE",
        num_args = 1..=2,
        required = true
    )]
    wordlists: Vec<PathBuf>,

    /// Pairing mode when two wordlists are supplied.
    #[arg(long = "mode", value_enum, default_value_t = ModeArg::Clusterbomb)]
    mode: ModeArg,

    /// HTTP method template.
    #[arg(short = 'X', long = "method", default_value = "GET")]
    method: String,

    /// Header template, `Name: Value`; repeatable.
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    headers: Vec<String>,

    /// Cookie header template.
    #[arg(short = 'b', long = "cookie", value_name = "COOKIE")]
    cookie: Option<String>,

    /// Request body template.
    #[arg(short = 'd', long = "data", value_name = "BODY")]
    body: Option<String>,

    /// Follow redirects.
    #[arg(short = 'r', long = "follow-redirects")]
    follow_redirects: bool,

    /// Skip TLS certificate verification.
    #[arg(short = 'k', long = "insecure")]
    insecure: bool,

    /// Proxy URL (HTTP/HTTPS proxy environment variables also work).
    #[arg(short = 'x', long = "proxy", value_name = "URL")]
    proxy: Option<String>,

    /// Concurrent requests (default: 40).
    #[arg(short = 't', long = "concurrency", default_value_t = 40)]
    concurrency: usize,

    /// Global requests/sec cap (default: none).
    #[arg(long = "rate", visible_alias = "rate-limit", value_name = "RPS")]
    rate: Option<f64>,

    /// Per-request timeout in seconds.
    #[arg(long = "timeout", default_value_t = 10.0)]
    timeout: f64,

    /// Retry count per request (capped at 10).
    #[arg(long = "retries", default_value_t = 2)]
    retries: u32,

    /// Pause new work when the rolling error rate reaches this ratio (0, 1].
    #[arg(long = "error-threshold", value_name = "RATIO")]
    error_threshold: Option<f64>,

    /// Rolling error window size.
    #[arg(long = "error-window", default_value_t = 50)]
    error_window: usize,

    /// Minimum samples before the circuit breaker can open.
    #[arg(long = "error-min-samples", default_value_t = 20)]
    error_min_samples: usize,

    /// Circuit-breaker pause duration in seconds.
    #[arg(long = "error-cooldown", default_value_t = 5.0)]
    error_cooldown: f64,

    /// Calibrate with random entries and auto-filter matching baselines.
    #[arg(short = 'a', long = "calibrate")]
    calibrate: bool,

    /// Number of random calibration probes.
    #[arg(long = "calibration-requests", default_value_t = 3)]
    calibration_requests: usize,

    /// Queue discovered directory paths (URLs ending in `/`) for fuzzing.
    #[arg(long = "recursion")]
    recursion: bool,

    /// Maximum recursion depth.
    #[arg(long = "recursion-depth", default_value_t = 2)]
    recursion_depth: usize,

    /// Append each extension to every FUZZ entry.
    #[arg(short = 'e', long = "extensions", value_delimiter = ',')]
    extensions: Vec<String>,

    /// Matcher status codes/ranges (default: 200-299,301,302,307,401,403,405,500).
    #[arg(long = "match-status", value_delimiter = ',')]
    match_status: Vec<String>,

    /// Matcher body sizes in bytes.
    #[arg(long = "match-size", value_delimiter = ',')]
    match_size: Vec<String>,

    /// Matcher word counts.
    #[arg(long = "match-words", value_delimiter = ',')]
    match_words: Vec<String>,

    /// Matcher line counts.
    #[arg(long = "match-lines", value_delimiter = ',')]
    match_lines: Vec<String>,

    /// Matcher body regex; repeatable.
    #[arg(long = "match-regex")]
    match_regex: Vec<String>,

    /// Matcher response-time range in milliseconds, e.g. `100-500`.
    #[arg(long = "match-time")]
    match_time: Option<String>,

    /// Filter status codes/ranges.
    #[arg(long = "filter-status", value_delimiter = ',')]
    filter_status: Vec<String>,

    /// Filter body sizes in bytes.
    #[arg(long = "filter-size", value_delimiter = ',')]
    filter_size: Vec<String>,

    /// Filter word counts.
    #[arg(long = "filter-words", value_delimiter = ',')]
    filter_words: Vec<String>,

    /// Filter line counts.
    #[arg(long = "filter-lines", value_delimiter = ',')]
    filter_lines: Vec<String>,

    /// Filter body regex; repeatable.
    #[arg(long = "filter-regex")]
    filter_regex: Vec<String>,

    /// Filter response-time range in milliseconds, e.g. `100-500`.
    #[arg(long = "filter-time")]
    filter_time: Option<String>,

    /// Write JSONL events plus the stats trailer to this file.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Terminal output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(Args)]
struct DnsArgs {
    /// Base domain to brute-force below.
    #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
    domain: String,

    /// Wordlist of subdomain labels.
    #[arg(short = 'w', long = "wordlist", value_name = "FILE", required = true)]
    wordlist: PathBuf,

    /// Resolver IP or IP:PORT; repeatable or comma-separated. Default: system resolver.
    #[arg(long = "resolver", value_delimiter = ',', value_name = "ADDR")]
    resolvers: Vec<String>,

    /// Also query CNAME records (A and AAAA are always queried).
    #[arg(long = "cname")]
    cname: bool,

    /// Keep wildcard answers, tagged `wildcard: true`.
    #[arg(long = "show-wildcards")]
    show_wildcards: bool,

    /// Random probes used to detect per-level wildcards (0 disables).
    #[arg(long = "wildcard-probes", default_value_t = 3)]
    wildcard_probes: usize,

    /// Write kept hosts as plain Vedette-compatible lines on stdout.
    #[arg(long = "emit-hosts")]
    emit_hosts: bool,

    /// Append this port to `--emit-hosts` lines (`host:port`).
    #[arg(long = "emit-port", value_name = "PORT")]
    emit_port: Option<u16>,

    /// Concurrent DNS candidates (hard closed-loop window; default: 128).
    #[arg(short = 't', long = "concurrency", default_value_t = 128)]
    concurrency: usize,

    /// Optional global lookups/sec cap (default: none; the window is the cap).
    #[arg(long = "rate", visible_alias = "rate-limit", value_name = "RPS")]
    rate: Option<f64>,

    /// Per-record-type DNS timeout in seconds (default: 2, like c-ares).
    #[arg(long = "dns-timeout", default_value_t = 2.0)]
    dns_timeout: f64,

    /// Engine-level backstop timeout in seconds (default: 20).
    #[arg(long = "timeout", default_value_t = 20.0)]
    timeout: f64,

    /// Retry count per record type (capped at 10; default: 2, like c-ares).
    #[arg(long = "retries", default_value_t = 2)]
    retries: u32,

    /// Accepted for compatibility but ignored: DNS mode never runs a breaker.
    #[arg(long = "error-threshold", value_name = "RATIO")]
    error_threshold: Option<f64>,

    /// Accepted for compatibility but ignored: DNS mode never runs a breaker.
    #[arg(long = "error-window", default_value_t = 50)]
    error_window: usize,

    /// Accepted for compatibility but ignored: DNS mode never runs a breaker.
    #[arg(long = "error-min-samples", default_value_t = 20)]
    error_min_samples: usize,

    /// Accepted for compatibility but ignored: DNS mode never runs a breaker.
    #[arg(long = "error-cooldown", default_value_t = 5.0)]
    error_cooldown: f64,

    /// Write JSONL events plus the stats trailer to this file.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Terminal output format.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum ModeArg {
    Pitchfork,
    Clusterbomb,
}

impl From<ModeArg> for Mode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Pitchfork => Mode::Pitchfork,
            ModeArg::Clusterbomb => Mode::Clusterbomb,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Human,
    Jsonl,
}

#[tokio::main]
async fn main() {
    if let Err(error) = cli().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn cli() -> Result<()> {
    match Cli::parse().command {
        Command::Http(args) => run_http(args).await,
        Command::Dns(args) => run_dns(args).await,
    }
}

async fn run_http(args: HttpArgs) -> Result<()> {
    if args.concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    if !args.timeout.is_finite() || args.timeout <= 0.0 {
        bail!("--timeout must be greater than 0");
    }
    if let Some(rate) = args.rate {
        if !rate.is_finite() || rate <= 0.0 {
            bail!("--rate must be greater than 0");
        }
    }

    let mut headers = Vec::with_capacity(args.headers.len());
    for raw in &args.headers {
        let (name, value) = raw
            .split_once(':')
            .with_context(|| format!("header `{raw}` is missing `:`"))?;
        headers.push((name.trim().to_string(), value.trim_start().to_string()));
    }

    let template = HttpTemplate {
        url: args.url.clone(),
        method: args.method.clone(),
        headers,
        cookie: args.cookie.clone(),
        body: args.body.clone(),
    };

    let match_statuses = if args.match_status.is_empty() {
        vec![DEFAULT_MATCH_STATUSES.to_string()]
    } else {
        args.match_status.clone()
    };
    let selector = Selector {
        matchers: Criteria {
            status: parse_statuses(&match_statuses)?,
            size: parse_numbers(&args.match_size)?,
            words: parse_numbers(&args.match_words)?,
            lines: parse_numbers(&args.match_lines)?,
            regex: compile_regexes(&args.match_regex).context("invalid --match-regex")?,
            time_ms: args
                .match_time
                .as_deref()
                .map(TimeRange::parse)
                .transpose()
                .map_err(anyhow::Error::msg)?,
        },
        filters: Criteria {
            status: parse_statuses(&args.filter_status)?,
            size: parse_numbers(&args.filter_size)?,
            words: parse_numbers(&args.filter_words)?,
            lines: parse_numbers(&args.filter_lines)?,
            regex: compile_regexes(&args.filter_regex).context("invalid --filter-regex")?,
            time_ms: args
                .filter_time
                .as_deref()
                .map(TimeRange::parse)
                .transpose()
                .map_err(anyhow::Error::msg)?,
        },
    };

    let circuit_breaker = match args.error_threshold {
        Some(threshold) => {
            if !threshold.is_finite() || threshold <= 0.0 || threshold > 1.0 {
                bail!("--error-threshold must be in (0, 1]");
            }
            if !args.error_cooldown.is_finite() || args.error_cooldown <= 0.0 {
                bail!("--error-cooldown must be greater than 0");
            }
            Some(CircuitBreakerConfig {
                window: args.error_window.max(1),
                error_threshold: threshold,
                min_samples: args.error_min_samples.max(1),
                cooldown: Duration::from_secs_f64(args.error_cooldown),
            })
        }
        None => None,
    };

    let engine = Engine::new(EngineConfig {
        concurrency: args.concurrency,
        rate_limit: args.rate,
        timeout: Duration::from_secs_f64(args.timeout),
        retries: args.retries.min(10),
        retry_base_delay: Duration::from_millis(100),
        circuit_breaker,
    });

    let client = build_client(&HttpOptions {
        follow_redirects: args.follow_redirects,
        insecure: args.insecure,
        proxy: args.proxy.clone(),
        user_agent: None,
    })?;

    let spec = WordlistSpec::new(
        args.wordlists[0].clone(),
        args.wordlists.get(1).cloned(),
        args.mode.into(),
    );
    let extensions: Vec<String> = args
        .extensions
        .iter()
        .map(|extension| extension.trim().to_string())
        .filter(|extension| !extension.is_empty())
        .collect();

    let mut sinks: Vec<JsonlWriter<Box<dyn Write>>> = Vec::new();
    if args.format == OutputFormat::Jsonl {
        sinks.push(JsonlWriter::new(Box::new(
            BufWriter::new(std::io::stdout()),
        )));
    }
    if let Some(path) = &args.output {
        let file = File::create(path)
            .with_context(|| format!("cannot create output file {}", path.display()))?;
        sinks.push(JsonlWriter::new(Box::new(BufWriter::new(file))));
    }
    let mut human = (args.format == OutputFormat::Human).then(HumanTable::new);

    let mut queue: VecDeque<(HttpTemplate, usize)> = VecDeque::new();
    queue.push_back((template, 0));
    let mut visited: HashSet<String> = HashSet::new();
    let mut aggregate = RunStats::default();
    let overall_start = Instant::now();

    while let Some((current_template, depth)) = queue.pop_front() {
        if !visited.insert(current_template.url.clone()) {
            continue;
        }

        let target = HttpTarget::new(client.clone(), current_template.clone());
        let calibration = if args.calibrate {
            engine.calibrate(&target, args.calibration_requests).await
        } else {
            Calibration::default()
        };

        let words = spec
            .iter()
            .with_context(|| format!("cannot open wordlist {}", spec.first.display()))?;
        let words = expand_extensions(words, extensions.clone());

        let mut recursions = Vec::new();
        let mut output_error: Option<anyhow::Error> = None;

        let report = engine
            .run(words, &target, &selector, &calibration, |event| {
                if output_error.is_some() {
                    return;
                }
                if let Event::Result { info, .. } = &event {
                    if args.recursion {
                        if let Some(base) = recursion_base(info, depth, args.recursion_depth) {
                            recursions
                                .push((current_template.for_recursion_base(&base), depth + 1));
                        }
                    }
                }
                if let Some(table) = &mut human {
                    table.print(&event);
                }
                for sink in &mut sinks {
                    if let Err(error) = sink.write(&event) {
                        output_error = Some(anyhow::Error::new(error));
                        break;
                    }
                }
            })
            .await?;

        if let Some(error) = output_error {
            return Err(error).context("cannot write output");
        }

        aggregate.merge(&report.stats);
        if args.recursion {
            for item in recursions {
                if !visited.contains(&item.0.url) {
                    queue.push_back(item);
                }
            }
        }
    }

    let elapsed = overall_start.elapsed();
    let rps = if elapsed.as_secs_f64() > 0.0 {
        aggregate.requests as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let stats = Event::stats(&RunReport {
        stats: aggregate,
        elapsed,
        rps,
    });
    if let Some(table) = &mut human {
        table.print(&stats);
    }
    for sink in &mut sinks {
        sink.write(&stats)?;
        sink.flush()?;
    }

    Ok(())
}

async fn run_dns(args: DnsArgs) -> Result<()> {
    if args.concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    if !args.timeout.is_finite() || args.timeout <= 0.0 {
        bail!("--timeout must be greater than 0");
    }
    if !args.dns_timeout.is_finite() || args.dns_timeout <= 0.0 {
        bail!("--dns-timeout must be greater than 0");
    }
    if let Some(rate) = args.rate {
        if !rate.is_finite() || rate <= 0.0 {
            bail!("--rate must be greater than 0");
        }
    }
    if args.emit_hosts && args.format == OutputFormat::Jsonl && args.output.is_none() {
        bail!("--emit-hosts cannot share stdout with --format jsonl; write JSONL with -o");
    }

    let domain = args
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() {
        bail!("--domain cannot be empty");
    }

    // DNS mode intentionally has no circuit breaker: aiodnsbrute's closed-loop
    // window is the only admission control. The flags are still validated so
    // existing invocations do not silently change meaning, but they never open
    // a breaker here.
    if let Some(threshold) = args.error_threshold {
        if !threshold.is_finite() || threshold <= 0.0 || threshold > 1.0 {
            bail!("--error-threshold must be in (0, 1]");
        }
        if !args.error_cooldown.is_finite() || args.error_cooldown <= 0.0 {
            bail!("--error-cooldown must be greater than 0");
        }
    }
    let _ = (
        args.error_window,
        args.error_min_samples,
        args.error_cooldown,
        args.error_threshold,
    );

    let retries = args.retries.min(10);
    let dns_timeout = Duration::from_secs_f64(args.dns_timeout);
    // The engine timeout is only a backstop: make sure it can never cut off
    // the per-type timeout/retry budget configured above.
    let backstop = Duration::from_secs_f64(args.timeout)
        .max(dns_timeout.saturating_mul(retries.saturating_add(1)));
    let engine = Engine::new(EngineConfig {
        concurrency: args.concurrency,
        rate_limit: args.rate,
        timeout: backstop,
        // Per-record-type retries live in DnsTarget; the engine must never
        // re-execute a whole candidate because one type failed.
        retries: 0,
        retry_base_delay: Duration::from_millis(100),
        circuit_breaker: None,
    });

    let resolvers = build_resolvers(&args.resolvers)?;
    let mut target = DnsTarget::new(resolvers, domain, default_record_types(args.cname))
        .with_per_type_timeout(dns_timeout)
        .with_per_type_retries(retries);
    target.set_show_wildcards(args.show_wildcards);
    if args.wildcard_probes > 0 {
        // Let probe queries drain instead of cancelling siblings, so no
        // probe traffic overlaps the main run.
        target.set_cancel_siblings(false);
        let wildcards = target.detect_wildcards(&engine, args.wildcard_probes).await;
        target.set_wildcards(wildcards);
        target.set_cancel_siblings(true);
    }
    // Wildcard probes are not part of the run statistics.
    target.reset_dns_stats();

    let spec = WordlistSpec::new(args.wordlist.clone(), None, Mode::Clusterbomb);

    let mut sinks: Vec<JsonlWriter<Box<dyn Write>>> = Vec::new();
    if args.format == OutputFormat::Jsonl {
        sinks.push(JsonlWriter::new(Box::new(
            BufWriter::new(std::io::stdout()),
        )));
    }
    if let Some(path) = &args.output {
        let file = File::create(path)
            .with_context(|| format!("cannot create output file {}", path.display()))?;
        sinks.push(JsonlWriter::new(Box::new(BufWriter::new(file))));
    }
    let mut human = (args.format == OutputFormat::Human && !args.emit_hosts).then(HumanTable::new);
    let mut host_lines = args.emit_hosts.then(|| BufWriter::new(std::io::stdout()));

    let words = spec
        .iter()
        .with_context(|| format!("cannot open wordlist {}", spec.first.display()))?;

    let mut output_error: Option<anyhow::Error> = None;
    let report = engine
        .run(
            words,
            &target,
            &Selector::default(),
            &Calibration::default(),
            |event| {
                if output_error.is_some() {
                    return;
                }
                if let Event::Result { info, .. } = &event {
                    if let Some(writer) = host_lines.as_mut() {
                        if let Some(payload) = payload_from_info(info) {
                            if let Err(error) =
                                write_handoff_line(writer, &payload.host, args.emit_port)
                            {
                                output_error = Some(anyhow::Error::new(error));
                                return;
                            }
                        }
                    }
                }
                if let Some(table) = &mut human {
                    table.print(&event);
                }
                for sink in &mut sinks {
                    if let Err(error) = sink.write(&event) {
                        output_error = Some(anyhow::Error::new(error));
                        break;
                    }
                }
            },
        )
        .await?;

    if let Some(error) = output_error {
        return Err(error).context("cannot write output");
    }
    if let Some(writer) = host_lines.as_mut() {
        writer.flush().context("cannot flush host output")?;
    }

    let dns_stats = target.dns_stats();
    let stats = Event::stats_with_dns(&report, Some(dns_stats));
    if let Some(table) = &mut human {
        table.print(&stats);
    } else if args.emit_hosts {
        if let Event::Stats {
            requests,
            errors,
            kept,
            filtered,
            elapsed_ms,
            rps,
            ..
        } = &stats
        {
            eprintln!(
                "[stats] requests={requests} errors={errors} kept={kept} filtered={filtered} elapsed_ms={elapsed_ms} rps={rps:.2}"
            );
        }
    }
    for sink in &mut sinks {
        sink.write(&stats)?;
        sink.flush()?;
    }

    Ok(())
}

fn parse_statuses(values: &[String]) -> Result<Vec<u16>> {
    let mut statuses = Vec::new();
    for value in values {
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if part.eq_ignore_ascii_case("all") {
                return Ok(Vec::new());
            }
            if let Some((start, end)) = part.split_once('-') {
                let start: u16 = start
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid status range `{part}`"))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid status range `{part}`"))?;
                if start > end {
                    bail!("invalid status range `{part}`: start is greater than end");
                }
                statuses.extend(start..=end);
            } else {
                statuses.push(
                    part.parse()
                        .with_context(|| format!("invalid status code `{part}`"))?,
                );
            }
        }
    }
    statuses.sort_unstable();
    statuses.dedup();
    Ok(statuses)
}

fn parse_numbers(values: &[String]) -> Result<Vec<usize>> {
    let mut numbers = Vec::new();
    for value in values {
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            numbers.push(
                part.parse()
                    .with_context(|| format!("invalid number `{part}`"))?,
            );
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    Ok(numbers)
}
