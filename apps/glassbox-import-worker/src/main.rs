use glassbox_import_worker::{translate, translate_packet_capture};
use std::io::{self, BufReader, BufWriter};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    if std::env::var_os("GLASSBOX_EXPECT_NO_NETWORK").is_some() {
        let address = SocketAddr::from(([127, 0, 0, 1], 9));
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            result => {
                eprintln!("network confinement failed: {result:?}");
                return ExitCode::from(3);
            }
        }
    }
    let source_format =
        std::env::var("GLASSBOX_SOURCE_FORMAT").unwrap_or_else(|_| "fixture-ndjson-v1".into());
    let result = if source_format == "pcap-v1"
        || source_format == "pcapng-v1"
        || source_format == "packet-capture-v1"
    {
        let capture_source =
            std::env::var("GLASSBOX_CAPTURE_SOURCE").unwrap_or_else(|_| "selected_capture".into());
        let capture_session =
            std::env::var("GLASSBOX_CAPTURE_SESSION").unwrap_or_else(|_| "import_session".into());
        translate_packet_capture(
            BufReader::new(io::stdin().lock()),
            BufWriter::new(io::stdout().lock()),
            &capture_source,
            &capture_session,
        )
    } else {
        translate(
            BufReader::new(io::stdin().lock()),
            BufWriter::new(io::stdout().lock()),
            &source_format,
        )
    };
    match result {
        Ok(stats) => {
            eprintln!("observations={} relations={}", stats.observations, stats.relations);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("import rejected: {error}");
            ExitCode::from(2)
        }
    }
}
