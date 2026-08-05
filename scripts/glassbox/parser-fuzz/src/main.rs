//! Deterministic mutation fuzz oracle for hostile Glassbox parsers.

use glassbox_apple_log_import::parse as parse_apple_log;
use glassbox_har_import::parse as parse_har;
use glassbox_network_import::parse as parse_packet_capture;
use glassbox_otlp_import::parse as parse_otlp;
use serde::Serialize;
use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

const CASES_PER_PARSER: u64 = 4_096;
const MAX_MUTATED_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct FuzzStats {
    cases: u64,
    accepted: u64,
    rejected: u64,
    panics: u64,
}

#[derive(Debug, Serialize)]
struct Receipt {
    schema_version: &'static str,
    deterministic_seed: u64,
    max_mutated_bytes: usize,
    har: FuzzStats,
    evidence_bundle: FuzzStats,
    otlp: FuzzStats,
    packet_capture: FuzzStats,
    apple_log_projection: FuzzStats,
    ok: bool,
}

fn main() {
    let deterministic_seed = 0x676c_6173_7362_6f78;
    let har_seed =
        include_bytes!("../../../../crates/glassbox-fixtures/corpus/hostile-import/har/valid.har");
    let packet_seed = decode_hex(include_str!(
        "../../../../crates/glassbox-fixtures/corpus/network-import/valid-little.pcap.hex"
    ));
    let otlp_seed = include_bytes!(
        "../../../../crates/glassbox-fixtures/corpus/hostile-import/otlp/valid-traces.jsonl"
    );
    let fixture = gate1_fixture();
    let apple_log_seed = include_bytes!(
        "../../../../crates/glassbox-fixtures/corpus/hostile-import/apple-log/valid.ndjson"
    );
    let mut bundle_seed = Vec::new();
    write_lossless(&mut bundle_seed, &fixture.observations, &fixture.relations).unwrap();

    let har = fuzz(har_seed, deterministic_seed, |bytes| {
        parse_har(Cursor::new(bytes), "fuzz_har", |_| Ok(())).is_ok()
    });
    let packet_capture = fuzz(&packet_seed, deterministic_seed ^ u64::MAX, |bytes| {
        parse_packet_capture(Cursor::new(bytes), "fuzz_pcap", |_| Ok(())).is_ok()
    });
    let otlp = fuzz(otlp_seed, deterministic_seed.rotate_left(17), |bytes| {
        parse_otlp(Cursor::new(bytes), "fuzz_otlp", |_| Ok(())).is_ok()
    });
    let evidence_bundle = fuzz(&bundle_seed, deterministic_seed.rotate_right(11), |bytes| {
        read_bundle(Cursor::new(bytes), |_| Ok(())).is_ok()
    });
    let apple_log_projection = fuzz(apple_log_seed, deterministic_seed.rotate_left(31), |bytes| {
        parse_apple_log(Cursor::new(bytes), |_| Ok(())).is_ok()
    });
    let receipt = Receipt {
        schema_version: "glassbox-parser-fuzz/v1",
        deterministic_seed,
        max_mutated_bytes: MAX_MUTATED_BYTES,
        har,
        evidence_bundle,
        otlp,
        packet_capture,
        apple_log_projection,
        ok: har.panics == 0
            && evidence_bundle.panics == 0
            && otlp.panics == 0
            && packet_capture.panics == 0
            && apple_log_projection.panics == 0
            && har.cases == CASES_PER_PARSER
            && evidence_bundle.cases == CASES_PER_PARSER
            && otlp.cases == CASES_PER_PARSER
            && packet_capture.cases == CASES_PER_PARSER
            && apple_log_projection.cases == CASES_PER_PARSER,
    };
    println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
    if !receipt.ok {
        std::process::exit(1);
    }
}

fn fuzz<F>(seed: &[u8], mut state: u64, mut parse: F) -> FuzzStats
where
    F: FnMut(Vec<u8>) -> bool,
{
    let mut stats = FuzzStats::default();
    for case in 0..CASES_PER_PARSER {
        let mut candidate = seed.to_vec();
        if case % 509 != 0 {
            let mutations = 1 + (next(&mut state) % 8) as usize;
            for _ in 0..mutations {
                mutate(&mut candidate, &mut state);
            }
        }
        if case % 257 == 0 && case % 509 != 0 {
            candidate.clear();
        }
        stats.cases += 1;
        match catch_unwind(AssertUnwindSafe(|| parse(candidate))) {
            Ok(true) => stats.accepted += 1,
            Ok(false) => stats.rejected += 1,
            Err(_) => stats.panics += 1,
        }
    }
    stats
}

fn mutate(bytes: &mut Vec<u8>, state: &mut u64) {
    match next(state) % 4 {
        0 if !bytes.is_empty() => {
            let index = next(state) as usize % bytes.len();
            bytes[index] ^= 1 << (next(state) % 8);
        }
        1 if !bytes.is_empty() => {
            bytes.truncate(next(state) as usize % bytes.len());
        }
        2 if bytes.len() < MAX_MUTATED_BYTES => {
            let index = next(state) as usize % (bytes.len() + 1);
            bytes.insert(index, next(state) as u8);
        }
        _ if !bytes.is_empty() => {
            let start = next(state) as usize % bytes.len();
            let end = (start + 1 + (next(state) % 16) as usize).min(bytes.len());
            bytes[start..end].fill(next(state) as u8);
        }
        _ => bytes.push(next(state) as u8),
    }
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn decode_hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|byte| byte.is_ascii_hexdigit()).collect();
    assert_eq!(digits.len() % 2, 0);
    digits.chunks_exact(2).map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1])).collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!(),
    }
}
use glassbox_evidence_bundle::{read_bundle, write_lossless};
use glassbox_fixtures::gate1_fixture;
