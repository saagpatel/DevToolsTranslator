use glassbox_evidence_bundle::write_lossless;
use glassbox_fixtures::gate1_fixture;
use std::io::{self, Write};

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "valid".into());
    let mut fixture = gate1_fixture();
    if mode == "duplicate" {
        fixture.observations.push(fixture.observations[0].clone());
    } else if mode != "valid" {
        eprintln!("expected valid or duplicate mode");
        std::process::exit(2);
    }
    let mut encoded = Vec::new();
    write_lossless(&mut encoded, &fixture.observations, &fixture.relations).unwrap();
    io::stdout().lock().write_all(&encoded).unwrap();
}
