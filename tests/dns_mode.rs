mod dns_fixture;

use std::time::Duration;

use dns_fixture::{DnsFixture, Zone};
use fathom::{
    Calibration, DnsTarget, Engine, EngineConfig, Event, Selector, WordSet, build_resolvers,
    default_record_types, handoff_line, payload_from_info,
};

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
    // Vedette's input parser accepts a bare host and host:port on stdin/files.
    assert_eq!(handoff_line("admin.example.com", None), "admin.example.com");
    assert_eq!(
        handoff_line("admin.example.com", Some(8443)),
        "admin.example.com:8443"
    );
}
