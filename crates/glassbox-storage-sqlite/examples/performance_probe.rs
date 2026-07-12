use glassbox_contracts::{
    LineageId, MaterializationId, NativeObservation, SemanticObservationId, SourceTrust,
    TimeInterval,
};
use glassbox_storage_sqlite::SqlCipherRepository;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Instant;

const BATCH_SIZE: usize = 1_000;
const PAGE_SIZE: usize = 100;
const NAVIGATION_SAMPLES: usize = 250;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let event_count =
        std::env::args().nth(1).unwrap_or_else(|| "1000000".into()).parse::<usize>()?;
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("million-event.sqlite3");
    let mut repository = SqlCipherRepository::create(&path, [0x61; 32])?;
    let ingest_started = Instant::now();
    let mut inserted = 0_usize;
    let mut explicit_gap_markers = 0_usize;
    for batch_start in (0..event_count).step_by(BATCH_SIZE) {
        let batch_end = (batch_start + BATCH_SIZE).min(event_count);
        let mut observations = Vec::with_capacity(batch_end - batch_start);
        for ordinal in batch_start..batch_end {
            let is_gap = ordinal % 100_000 == 99_999;
            explicit_gap_markers += usize::from(is_gap);
            let native_id = format!("event-{ordinal:010}");
            let semantic_id =
                SemanticObservationId::derive("performance_fixture", "million-event", &native_id);
            let mut fields = BTreeMap::from([
                ("fixture_variant".into(), format!("cardinality-{}", ordinal % 65_537)),
                ("coverage".into(), "complete".into()),
            ]);
            if is_gap {
                fields.insert("coverage".into(), "explicit_gap".into());
                fields.insert("gap_reason".into(), "fixture_injected".into());
            }
            observations.push(NativeObservation {
                semantic_id,
                materialization_id: MaterializationId(format!("perf-mat-{ordinal:010}")),
                lineage_id: LineageId(format!("perf-lineage-{ordinal:010}")),
                source_kind: "performance_fixture".into(),
                capture_session: "million-event".into(),
                native_id,
                observed_time: TimeInterval::new(ordinal as i128 * 1_000, ordinal as i128 * 1_000)?,
                trust: SourceTrust::SourceDeclared,
                fields,
            });
        }
        let result = repository.publish_atomic(
            &format!("performance-batch-{batch_start:010}"),
            &observations,
            &[],
        )?;
        inserted += result.inserted;
    }
    let ingest_seconds = ingest_started.elapsed().as_secs_f64();
    let stored_count = repository.observation_count()?;

    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut navigation_us = Vec::with_capacity(NAVIGATION_SAMPLES);
    let mut pages_complete = true;
    let mut addressable = true;
    for sample in 0..NAVIGATION_SAMPLES {
        state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let leading_nibble = sample % 15;
        let cursor = format!("obs:{leading_nibble:x}{state:016x}");
        let started = Instant::now();
        let page = repository.observation_page_after(Some(&cursor), PAGE_SIZE)?;
        navigation_us.push(started.elapsed().as_micros() as u64);
        pages_complete &= page.observations.len() == PAGE_SIZE;
        addressable &= page
            .observations
            .iter()
            .all(|item| !item.semantic_id.as_str().is_empty() && !item.native_id.is_empty());
    }
    navigation_us.sort_unstable();
    let p95_index = (navigation_us.len() * 95).div_ceil(100).saturating_sub(1);
    let p95_navigation_ms = navigation_us[p95_index] as f64 / 1_000.0;
    let max_navigation_ms = *navigation_us.last().unwrap_or(&0) as f64 / 1_000.0;
    let database_bytes = std::fs::metadata(&path)?.len();
    let wal_bytes = std::fs::metadata(path.with_extension("sqlite3-wal"))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema_version": "glassbox-performance-probe/v1",
            "event_count": event_count,
            "inserted_count": inserted,
            "stored_count": stored_count,
            "batch_size": BATCH_SIZE,
            "page_size": PAGE_SIZE,
            "navigation_samples": NAVIGATION_SAMPLES,
            "ingest_seconds": ingest_seconds,
            "p95_navigation_ms": p95_navigation_ms,
            "max_navigation_ms": max_navigation_ms,
            "database_bytes": database_bytes,
            "wal_bytes": wal_bytes,
            "explicit_gap_markers": explicit_gap_markers,
            "unmarked_drops": event_count.saturating_sub(stored_count),
            "pages_complete": pages_complete,
            "addressable_evidence": addressable,
        }))?
    );
    Ok(())
}
