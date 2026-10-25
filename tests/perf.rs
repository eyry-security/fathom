mod common;
mod dns_fixture;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Arc;
use std::time::Duration;

use common::{FixtureServer, TestResponse};
use dns_fixture::{DnsFixture, Zone};
use fathom::{
    Calibration, DnsTarget, Engine, EngineConfig, Event, HttpOptions, HttpTarget, HttpTemplate,
    Selector, WordSet, WordlistSpec, build_client, build_resolvers, default_record_types,
};

#[tokio::test]
async fn ten_thousand_requests_complete_without_error_blowup() {
    let server = FixtureServer::start(Arc::new(|_request: &common::Request| {
        TestResponse::ok("ok")
    }))
    .await;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("perf.txt");
    let file = File::create(&path).unwrap();
    let mut writer = BufWriter::new(file);
    for index in 0..10_000 {
        writeln!(writer, "entry{index}").unwrap();
    }
    writer.flush().unwrap();

    let spec = WordlistSpec::new(path, None, fathom::Mode::Clusterbomb);
    let client = build_client(&HttpOptions::default()).unwrap();
    let target = HttpTarget::new(
        client,
        HttpTemplate {
            url: format!("{}/FUZZ", server.base_url()),
            method: "GET".to_string(),
            headers: Vec::new(),
            cookie: None,
            body: None,
        },
    );
    let engine = Engine::new(EngineConfig {
        concurrency: 64,
        rate_limit: None,
        timeout: Duration::from_secs(5),
        retries: 0,
        retry_base_delay: Duration::from_millis(10),
        circuit_breaker: None,
    });

    let mut kept = 0u64;
    let report = engine
        .run(
            spec.iter().unwrap(),
            &target,
            &Selector::default(),
            &Calibration::default(),
            |event| {
                if matches!(event, Event::Result { .. }) {
                    kept += 1;
                }
            },
        )
        .await
        .unwrap();

    println!(
        "perf smoke: requests={} errors={} kept={} elapsed={:.3}s rps={:.1}",
        report.stats.requests,
        report.stats.errors,
        report.stats.kept,
        report.elapsed.as_secs_f64(),
        report.rps
    );

    assert_eq!(report.stats.requests, 10_000);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(report.stats.kept, 10_000);
    assert_eq!(kept, 10_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_fixture_perf_smoke() {
    const LOOKUPS: usize = 20_000;
    const RECORD_TYPES: usize = 2;

    let fixture = DnsFixture::start(Zone::test_zone()).await;
    let resolvers = build_resolvers(&[fixture.resolver_spec()]).unwrap();
    let mut target = DnsTarget::new(resolvers, "example.test", default_record_types(false));
    target.set_show_wildcards(true);
    let engine = Engine::new(EngineConfig {
        concurrency: 64,
        rate_limit: None,
        timeout: Duration::from_secs(5),
        retries: 0,
        retry_base_delay: Duration::from_millis(10),
        circuit_breaker: None,
    });

    let words = (0..LOOKUPS).map(|index| Ok(WordSet::single(format!("perf-{index}"))));
    let report = engine
        .run(
            words,
            &target,
            &Selector::default(),
            &Calibration::default(),
            |_| {},
        )
        .await
        .unwrap();

    let dns_queries_per_second = report.rps * RECORD_TYPES as f64;
    println!(
        "dns perf smoke: lookups={} errors={} kept={} elapsed={:.3}s host_lookups/s={:.1} dns_queries/s~={:.1}",
        report.stats.requests,
        report.stats.errors,
        report.stats.kept,
        report.elapsed.as_secs_f64(),
        report.rps,
        dns_queries_per_second
    );

    assert_eq!(report.stats.requests, LOOKUPS as u64);
    assert_eq!(report.stats.errors, 0);
    assert_eq!(report.stats.kept, LOOKUPS as u64);
}
