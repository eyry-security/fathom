mod dns_fixture;

use std::process::Command;
use std::time::Duration;

use dns_fixture::{DnsFixture, Zone};
use fathom::{
    Calibration, DnsTarget, Engine, EngineConfig, Event, Selector, WordSet, build_resolvers,
    default_record_types, handoff_line, payload_from_info, write_handoff_line,
};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};

async fn engine(concurrency: usize) -> Engine {
    Engine::new(EngineConfig {
        concurrency,
        rate_limit: None,
        timeout: Duration::from_secs(2),
        retries: 0,
        retry_base_delay: Duration::from_millis(10),
        circuit_breaker: None,
    })
}

async fn target(fixture: &DnsFixture, cname: bool, show_wildcards: bool) -> DnsTarget {
    let resolvers = build_resolvers(&[fixture.resolver_spec()]).unwrap();
    let mut target = DnsTarget::new(resolvers, "example.test", default_record_types(cname));
    let engine = engine(8).await;
    let wildcards = target.detect_wildcards(&engine, 3).await;
    target.set_wildcards(wildcards);
    target.set_show_wildcards(show_wildcards);
    target
}

fn words(values: &[&str]) -> Vec<std::io::Result<WordSet>> {
    values
        .iter()
        .map(|value| Ok(WordSet::single(*value)))
        .collect()
}

fn hosts(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Result { info, .. } => payload_from_info(info).map(|payload| payload.host),
            Event::Stats { .. } => None,
        })
        .collect()
}

#[tokio::test]
async fn brute_force_returns_real_hosts_and_filters_wildcard_answers() {
    let fixture = DnsFixture::start(Zone::test_zone()).await;
    let target = target(&fixture, false, false).await;
    let engine = engine(8).await;

    let mut events = Vec::new();
    let report = engine
        .run(
            words(&["www", "mail", "nope-one", "nope-two", "anything"]).into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |event| events.push(event),
        )
        .await
        .unwrap();

    let mut found = hosts(&events);
    found.sort();
    assert_eq!(found, vec!["mail.example.test", "www.example.test"]);
    assert_eq!(report.stats.requests, 5);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(report.stats.kept, 2);
    assert_eq!(report.stats.filtered, 3);
}

#[tokio::test]
async fn show_wildcards_keeps_and_tags_wildcard_results() {
    let fixture = DnsFixture::start(Zone::test_zone()).await;
    let target = target(&fixture, false, true).await;
    let engine = engine(8).await;

    let mut events = Vec::new();
    engine
        .run(
            words(&["anything", "www"]).into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |event| events.push(event),
        )
        .await
        .unwrap();

    let mut tagged = Vec::new();
    for event in &events {
        if let Event::Result { info, .. } = event {
            let payload = payload_from_info(info).unwrap();
            tagged.push((payload.host, payload.wildcard));
        }
    }
    tagged.sort();
    assert_eq!(
        tagged,
        vec![
            ("anything.example.test".to_string(), true),
            ("www.example.test".to_string(), false),
        ]
    );
}

#[tokio::test]
async fn cname_mode_reports_cname_records() {
    let fixture = DnsFixture::start(Zone::test_zone()).await;
    let target = target(&fixture, true, true).await;
    let engine = engine(4).await;

    let mut events = Vec::new();
    engine
        .run(
            words(&["cname"]).into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |event| events.push(event),
        )
        .await
        .unwrap();

    let payload = events
        .iter()
        .find_map(|event| match event {
            Event::Result { info, .. } => payload_from_info(info),
            Event::Stats { .. } => None,
        })
        .unwrap();
    assert!(payload.record_types.iter().any(|kind| kind == "CNAME"));
    assert!(
        payload.answers.iter().any(|answer| {
            answer.record_type == "CNAME" && answer.value == "target.example.test"
        })
    );
    assert!(
        payload
            .answers
            .iter()
            .any(|answer| { answer.record_type == "A" && answer.value == "192.0.2.30" })
    );
}

#[tokio::test]
async fn nxdomain_storm_does_not_trip_the_error_breaker() {
    let mut zone = Zone::test_zone();
    zone.clear_wildcard();
    let fixture = DnsFixture::start(zone).await;
    let resolvers = build_resolvers(&[fixture.resolver_spec()]).unwrap();
    let target = DnsTarget::new(resolvers, "example.test", default_record_types(false));
    let engine = Engine::new(EngineConfig {
        concurrency: 16,
        rate_limit: None,
        timeout: Duration::from_secs(2),
        retries: 0,
        retry_base_delay: Duration::from_millis(10),
        circuit_breaker: Some(fathom::CircuitBreakerConfig {
            window: 20,
            error_threshold: 0.1,
            min_samples: 5,
            cooldown: Duration::from_secs(5),
        }),
    });

    let words: Vec<_> = (0..200)
        .map(|index| Ok(WordSet::single(format!("missing-{index}"))))
        .collect();
    let report = engine
        .run(
            words.into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |_| {},
        )
        .await
        .unwrap();

    assert_eq!(report.stats.requests, 200);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(report.stats.kept, 0);
    assert_eq!(report.stats.filtered, 200);
    assert!(
        report.elapsed < Duration::from_secs(3),
        "breaker should not pause NXDOMAIN responses (elapsed {:?})",
        report.elapsed
    );
}

#[test]
fn handoff_lines_match_vedette_input_format() {
    // Vedette's input parser accepts a bare host and host:port on stdin/files
    // (src/input.rs: extract_host), skipping only empty and '#' lines.
    assert_eq!(handoff_line("admin.example.com", None), "admin.example.com");
    assert_eq!(
        handoff_line("admin.example.com", Some(8443)),
        "admin.example.com:8443"
    );

    let mut output = Vec::new();
    write_handoff_line(&mut output, "admin.example.com", None).unwrap();
    write_handoff_line(&mut output, "api.example.com", Some(8443)).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "admin.example.com\napi.example.com:8443\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn emit_hosts_cli_writes_only_vedette_input_lines() {
    let fixture = DnsFixture::start(Zone::test_zone()).await;
    let dir = tempfile::tempdir().unwrap();
    let wordlist = dir.path().join("subs.txt");
    std::fs::write(&wordlist, "www\nmail\nanything\n").unwrap();

    let binary = env!("CARGO_BIN_EXE_fathom");
    let resolver = fixture.resolver_spec();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(binary)
            .args([
                "dns",
                "-d",
                "example.test",
                "-w",
                wordlist.to_str().unwrap(),
                "--resolver",
                &resolver,
                "--concurrency",
                "1",
                "--emit-hosts",
            ])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        output.status.success(),
        "fathom failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut lines: Vec<_> = stdout.lines().collect();
    lines.sort();
    assert_eq!(lines, vec!["mail.example.test", "www.example.test"]);
    assert!(!stdout.contains("[stats]"));
}

#[tokio::test]
async fn partial_answer_survives_a_timed_out_record_type() {
    let mut zone = Zone::test_zone();
    zone.clear_wildcard();
    zone.add(
        "partial.example.test",
        300,
        RData::A(hickory_proto::rr::rdata::A("192.0.2.50".parse().unwrap())),
    );
    zone.drop_type("partial.example.test", RecordType::AAAA);
    let fixture = DnsFixture::start(zone).await;
    let resolvers = build_resolvers(&[fixture.resolver_spec()]).unwrap();
    let target = DnsTarget::new(resolvers, "example.test", default_record_types(false))
        .with_per_type_timeout(Duration::from_millis(500))
        .with_per_type_retries(0);

    let mut events = Vec::new();
    let report = engine(4)
        .await
        .run(
            words(&["partial"]).into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |event| events.push(event),
        )
        .await
        .unwrap();

    assert_eq!(report.stats.kept, 1);
    assert_eq!(report.stats.errors, 0);
    let payload = events
        .iter()
        .find_map(|event| match event {
            Event::Result { info, .. } => payload_from_info(info),
            Event::Stats { .. } => None,
        })
        .unwrap();
    assert!(
        payload
            .answers
            .iter()
            .any(|answer| { answer.record_type == "A" && answer.value == "192.0.2.50" })
    );
    assert_eq!(payload.incomplete_types, vec!["AAAA"]);
    let aaaa = payload
        .type_stats
        .iter()
        .find(|stat| stat.record_type == "AAAA")
        .unwrap();
    assert_eq!(aaaa.attempts, 1);
    assert_eq!(aaaa.timeouts, 1);
    assert_eq!(aaaa.incomplete, 1);

    let totals = target.dns_stats();
    let aaaa_totals = totals.per_type.get("AAAA").unwrap();
    assert_eq!(aaaa_totals.timeouts, 1);
    assert_eq!(aaaa_totals.incomplete, 1);
    assert_eq!(totals.rcodes.get("NOERROR"), Some(&1));
}

#[tokio::test]
async fn servfail_is_retried_per_type_and_counted() {
    let mut zone = Zone::new();
    zone.fail_type("fail.example.test", RecordType::A, ResponseCode::ServFail);
    zone.fail_type(
        "fail.example.test",
        RecordType::AAAA,
        ResponseCode::ServFail,
    );
    let fixture = DnsFixture::start(zone).await;
    let resolvers = build_resolvers(&[fixture.resolver_spec()]).unwrap();
    let target = DnsTarget::new(resolvers, "example.test", default_record_types(false))
        .with_per_type_timeout(Duration::from_millis(200))
        .with_per_type_retries(1);

    let report = engine(4)
        .await
        .run(
            words(&["fail"]).into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |_| {},
        )
        .await
        .unwrap();

    // One candidate, not one retry of the whole candidate.
    assert_eq!(report.stats.requests, 1);
    assert_eq!(report.stats.errors, 1);

    let totals = target.dns_stats();
    for record_type in ["A", "AAAA"] {
        let type_totals = totals.per_type.get(record_type).unwrap();
        assert_eq!(type_totals.attempts, 2);
        assert_eq!(type_totals.incomplete, 1);
    }
    assert_eq!(totals.rcodes.get("SERVFAIL"), Some(&2));
}

#[tokio::test]
async fn nxdomain_and_nodata_are_negative_not_errors() {
    let mut zone = Zone::new();
    zone.add(
        "a-only.example.test",
        300,
        RData::A(hickory_proto::rr::rdata::A("192.0.2.40".parse().unwrap())),
    );
    let fixture = DnsFixture::start(zone).await;
    let resolvers = build_resolvers(&[fixture.resolver_spec()]).unwrap();
    let target = DnsTarget::new(resolvers, "example.test", default_record_types(false))
        .with_per_type_timeout(Duration::from_millis(200))
        .with_per_type_retries(2);

    let report = engine(4)
        .await
        .run(
            words(&["a-only", "missing"]).into_iter(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |_| {},
        )
        .await
        .unwrap();

    assert_eq!(report.stats.requests, 2);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(report.stats.kept, 1);
    assert_eq!(report.stats.filtered, 1);

    let totals = target.dns_stats();
    // NXDOMAIN is authoritative for the whole name: AAAA is not sent for the
    // missing name, but it is still collected for the existing A-only name.
    assert_eq!(totals.rcodes.get("NXDOMAIN"), Some(&1));
    assert_eq!(totals.rcodes.get("NOERROR"), Some(&2));
    assert_eq!(totals.per_type.get("A").unwrap().attempts, 2);
    assert_eq!(totals.per_type.get("AAAA").unwrap().attempts, 1);
}
