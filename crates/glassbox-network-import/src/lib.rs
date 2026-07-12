//! Streaming, metadata-only PCAP and PCAPNG parser.
//!
//! Packet bytes are inspected only through a bounded header prefix and are never
//! retained in output records. The format cannot express process attribution, so
//! this API intentionally has no process field.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::io::{self, Read};
use thiserror::Error;

pub const MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_INTERFACE_BLOCK_BYTES: usize = 64 * 1024;
pub const MAX_PACKETS: u64 = 10_000_000;
const HEADER_PREFIX_BYTES: usize = 256;
const PCAPNG_SECTION: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketOpacity {
    HeaderOnly,
    OpaquePayload,
    TruncatedCapture,
    UnsupportedLinkType,
    MalformedHeaders,
}
impl PacketOpacity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HeaderOnly => "header_only",
            Self::OpaquePayload => "opaque_payload",
            Self::TruncatedCapture => "truncated_capture",
            Self::UnsupportedLinkType => "unsupported_link_type",
            Self::MalformedHeaders => "malformed_headers",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketRecord {
    pub capture_source: String,
    pub section_index: u32,
    pub interface_id: u32,
    pub interface_name: String,
    pub packet_ordinal: u64,
    pub native_locator: String,
    pub byte_offset: u64,
    pub captured_len: u32,
    pub original_len: u32,
    pub link_type: u32,
    pub timestamp_ns: i128,
    pub timestamp_resolution_ns: u64,
    pub network_protocol: Option<String>,
    pub source_address: Option<String>,
    pub destination_address: Option<String>,
    pub transport_protocol: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub opacity: PacketOpacity,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParseStats {
    pub packets: u64,
    pub captured_bytes: u64,
    pub truncated_packets: u64,
    pub opaque_packets: u64,
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}
impl Endian {
    fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        }
    }
    fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }
    fn i64(self, b: [u8; 8]) -> i64 {
        match self {
            Self::Little => i64::from_le_bytes(b),
            Self::Big => i64::from_be_bytes(b),
        }
    }
}

struct CountingReader<R> {
    inner: R,
    offset: u64,
}
impl<R: Read> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, offset: 0 }
    }
    fn exact(&mut self, bytes: &mut [u8]) -> Result<(), NetworkImportError> {
        self.inner.read_exact(bytes)?;
        self.offset = self
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or(NetworkImportError::LengthOverflow)?;
        Ok(())
    }
    fn optional_exact(&mut self, bytes: &mut [u8]) -> Result<bool, NetworkImportError> {
        let mut read = 0;
        while read < bytes.len() {
            match self.inner.read(&mut bytes[read..])? {
                0 if read == 0 => return Ok(false),
                0 => return Err(NetworkImportError::Truncated),
                count => {
                    read += count;
                    self.offset = self
                        .offset
                        .checked_add(count as u64)
                        .ok_or(NetworkImportError::LengthOverflow)?;
                }
            }
        }
        Ok(true)
    }
    fn skip(&mut self, mut bytes: usize) -> Result<(), NetworkImportError> {
        let mut buffer = [0_u8; 8192];
        while bytes > 0 {
            let count = bytes.min(buffer.len());
            self.exact(&mut buffer[..count])?;
            bytes -= count;
        }
        Ok(())
    }
}

pub fn parse<R: Read, F: FnMut(PacketRecord) -> Result<(), NetworkImportError>>(
    reader: R,
    capture_source: &str,
    mut sink: F,
) -> Result<ParseStats, NetworkImportError> {
    validate_source(capture_source)?;
    let mut reader = CountingReader::new(reader);
    let mut magic = [0_u8; 4];
    if !reader.optional_exact(&mut magic)? {
        return Err(NetworkImportError::EmptyInput);
    }
    if magic == PCAPNG_SECTION {
        parse_pcapng(&mut reader, capture_source, magic, &mut sink)
    } else {
        parse_pcap(&mut reader, capture_source, magic, &mut sink)
    }
}

fn parse_pcap<R: Read, F: FnMut(PacketRecord) -> Result<(), NetworkImportError>>(
    reader: &mut CountingReader<R>,
    source: &str,
    magic: [u8; 4],
    sink: &mut F,
) -> Result<ParseStats, NetworkImportError> {
    let (endian, units_per_second) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, 1_000_000_u128),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, 1_000_000_u128),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, 1_000_000_000_u128),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, 1_000_000_000_u128),
        _ => return Err(NetworkImportError::UnsupportedFormat),
    };
    let mut header = [0_u8; 20];
    reader.exact(&mut header)?;
    if endian.u16(header[0..2].try_into().unwrap()) != 2
        || endian.u16(header[2..4].try_into().unwrap()) != 4
    {
        return Err(NetworkImportError::UnsupportedVersion);
    }
    let snaplen = endian.u32(header[12..16].try_into().unwrap());
    let link_type = endian.u32(header[16..20].try_into().unwrap());
    validate_snaplen(snaplen)?;
    let mut stats = ParseStats::default();
    loop {
        let mut packet_header = [0_u8; 16];
        if !reader.optional_exact(&mut packet_header)? {
            break;
        }
        let seconds = endian.u32(packet_header[0..4].try_into().unwrap()) as u128;
        let fraction = endian.u32(packet_header[4..8].try_into().unwrap()) as u128;
        if fraction >= units_per_second {
            return Err(NetworkImportError::InvalidTimestamp);
        }
        let captured_len = endian.u32(packet_header[8..12].try_into().unwrap());
        let original_len = endian.u32(packet_header[12..16].try_into().unwrap());
        validate_packet_lengths(captured_len, original_len, snaplen)?;
        let byte_offset = reader.offset;
        let prefix = read_prefix_and_skip(reader, captured_len as usize)?;
        let timestamp_ns = seconds
            .checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(fraction.saturating_mul(1_000_000_000) / units_per_second))
            .and_then(|v| i128::try_from(v).ok())
            .ok_or(NetworkImportError::InvalidTimestamp)?;
        let record = packet_record(
            source,
            0,
            0,
            "interface-0",
            stats.packets,
            byte_offset,
            captured_len,
            original_len,
            link_type,
            timestamp_ns,
            resolution_ns(units_per_second),
            &prefix,
        );
        update_stats(&mut stats, &record)?;
        sink(record)?;
    }
    Ok(stats)
}

#[derive(Clone)]
struct Interface {
    link_type: u32,
    snaplen: u32,
    units_per_second: u128,
    name: String,
}

fn parse_pcapng<R: Read, F: FnMut(PacketRecord) -> Result<(), NetworkImportError>>(
    reader: &mut CountingReader<R>,
    source: &str,
    first_type: [u8; 4],
    sink: &mut F,
) -> Result<ParseStats, NetworkImportError> {
    let mut next_type = Some(first_type);
    let mut endian = Endian::Little;
    let mut section_index = 0_u32;
    let mut have_section = false;
    let mut interfaces: Vec<Interface> = vec![];
    let mut stats = ParseStats::default();
    loop {
        let block_type = if let Some(value) = next_type.take() {
            value
        } else {
            let mut value = [0; 4];
            if !reader.optional_exact(&mut value)? {
                break;
            }
            value
        };
        let mut length_bytes = [0; 4];
        reader.exact(&mut length_bytes)?;
        if block_type == PCAPNG_SECTION {
            let mut bom = [0; 4];
            reader.exact(&mut bom)?;
            endian = match bom {
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                _ => return Err(NetworkImportError::InvalidByteOrder),
            };
            let total = endian.u32(length_bytes) as usize;
            validate_block_length(total, 28)?;
            let mut version = [0; 4];
            reader.exact(&mut version)?;
            if endian.u16(version[0..2].try_into().unwrap()) != 1 {
                return Err(NetworkImportError::UnsupportedVersion);
            }
            let mut section_len = [0; 8];
            reader.exact(&mut section_len)?;
            let _ = endian.i64(section_len);
            reader.skip(total - 28)?;
            validate_trailer(reader, endian, total)?;
            if have_section {
                section_index =
                    section_index.checked_add(1).ok_or(NetworkImportError::LengthOverflow)?;
            }
            have_section = true;
            interfaces.clear();
            continue;
        }
        if !have_section {
            return Err(NetworkImportError::MissingSection);
        }
        let total = endian.u32(length_bytes) as usize;
        validate_block_length(total, 12)?;
        let body_len = total - 12;
        match endian.u32(block_type) {
            1 => {
                if body_len > MAX_INTERFACE_BLOCK_BYTES {
                    return Err(NetworkImportError::InterfaceBlockTooLarge(body_len));
                }
                let mut body = vec![0_u8; body_len];
                reader.exact(&mut body)?;
                validate_trailer(reader, endian, total)?;
                if body.len() < 8 {
                    return Err(NetworkImportError::InvalidBlockLength(total));
                }
                let link_type = endian.u16(body[0..2].try_into().unwrap()) as u32;
                let snaplen = endian.u32(body[4..8].try_into().unwrap());
                validate_snaplen(snaplen)?;
                let units = parse_ts_resolution(&body[8..], endian)?;
                let id = interfaces.len();
                interfaces.push(Interface {
                    link_type,
                    snaplen,
                    units_per_second: units,
                    name: format!("interface-{id}"),
                });
            }
            6 => {
                if body_len < 20 {
                    return Err(NetworkImportError::InvalidBlockLength(total));
                }
                let mut fixed = [0_u8; 20];
                reader.exact(&mut fixed)?;
                let interface_id = endian.u32(fixed[0..4].try_into().unwrap());
                let interface = interfaces
                    .get(interface_id as usize)
                    .ok_or(NetworkImportError::UnknownInterface(interface_id))?
                    .clone();
                let ticks = ((endian.u32(fixed[4..8].try_into().unwrap()) as u128) << 32)
                    | (endian.u32(fixed[8..12].try_into().unwrap()) as u128);
                let captured_len = endian.u32(fixed[12..16].try_into().unwrap());
                let original_len = endian.u32(fixed[16..20].try_into().unwrap());
                validate_packet_lengths(captured_len, original_len, interface.snaplen)?;
                let packet_offset = reader.offset;
                let prefix = read_prefix_and_skip(reader, captured_len as usize)?;
                let padding = (4 - (captured_len as usize % 4)) % 4;
                reader.skip(padding)?;
                let consumed = 20 + captured_len as usize + padding;
                if consumed > body_len {
                    return Err(NetworkImportError::InvalidBlockLength(total));
                }
                reader.skip(body_len - consumed)?;
                validate_trailer(reader, endian, total)?;
                let timestamp_ns = ticks
                    .checked_mul(1_000_000_000)
                    .map(|v| v / interface.units_per_second)
                    .and_then(|v| i128::try_from(v).ok())
                    .ok_or(NetworkImportError::InvalidTimestamp)?;
                let record = packet_record(
                    source,
                    section_index,
                    interface_id,
                    &interface.name,
                    stats.packets,
                    packet_offset,
                    captured_len,
                    original_len,
                    interface.link_type,
                    timestamp_ns,
                    resolution_ns(interface.units_per_second),
                    &prefix,
                );
                update_stats(&mut stats, &record)?;
                sink(record)?;
            }
            _ => {
                reader.skip(body_len)?;
                validate_trailer(reader, endian, total)?;
            }
        }
    }
    if !have_section {
        return Err(NetworkImportError::MissingSection);
    }
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn packet_record(
    source: &str,
    section: u32,
    interface: u32,
    name: &str,
    ordinal: u64,
    offset: u64,
    captured: u32,
    original: u32,
    link: u32,
    time: i128,
    resolution: u64,
    prefix: &[u8],
) -> PacketRecord {
    let mut record=PacketRecord{capture_source:source.into(),section_index:section,interface_id:interface,interface_name:name.into(),packet_ordinal:ordinal,native_locator:format!("pcap://{source}/section/{section}/interface/{interface}/packet/{ordinal}@{offset}+{captured}"),byte_offset:offset,captured_len:captured,original_len:original,link_type:link,timestamp_ns:time,timestamp_resolution_ns:resolution,network_protocol:None,source_address:None,destination_address:None,transport_protocol:None,source_port:None,destination_port:None,opacity:if captured<original{PacketOpacity::TruncatedCapture}else{PacketOpacity::HeaderOnly}};
    inspect_headers(&mut record, prefix);
    record
}

fn inspect_headers(record: &mut PacketRecord, bytes: &[u8]) {
    if record.link_type != 1 {
        record.opacity = PacketOpacity::UnsupportedLinkType;
        return;
    }
    if bytes.len() < 14 {
        record.opacity = PacketOpacity::MalformedHeaders;
        return;
    }
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    for _ in 0..2 {
        if matches!(ethertype, 0x8100 | 0x88a8) {
            if bytes.len() < offset + 4 {
                record.opacity = PacketOpacity::MalformedHeaders;
                return;
            }
            ethertype = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            offset += 4;
        }
    }
    let protocol = match ethertype {
        0x0800 => {
            if bytes.len() < offset + 20 {
                record.opacity = PacketOpacity::MalformedHeaders;
                return;
            }
            let ihl = ((bytes[offset] & 0x0f) as usize) * 4;
            if ihl < 20 || bytes.len() < offset + ihl {
                record.opacity = PacketOpacity::MalformedHeaders;
                return;
            }
            record.network_protocol = Some("ipv4".into());
            record.source_address = Some(format!(
                "{}.{}.{}.{}",
                bytes[offset + 12],
                bytes[offset + 13],
                bytes[offset + 14],
                bytes[offset + 15]
            ));
            record.destination_address = Some(format!(
                "{}.{}.{}.{}",
                bytes[offset + 16],
                bytes[offset + 17],
                bytes[offset + 18],
                bytes[offset + 19]
            ));
            let p = bytes[offset + 9];
            offset += ihl;
            p
        }
        0x86dd => {
            if bytes.len() < offset + 40 {
                record.opacity = PacketOpacity::MalformedHeaders;
                return;
            }
            record.network_protocol = Some("ipv6".into());
            record.source_address = Some(format_ipv6(&bytes[offset + 8..offset + 24]));
            record.destination_address = Some(format_ipv6(&bytes[offset + 24..offset + 40]));
            let p = bytes[offset + 6];
            offset += 40;
            p
        }
        _ => {
            record.opacity = PacketOpacity::OpaquePayload;
            return;
        }
    };
    match protocol {
        6 => {
            if bytes.len() < offset + 20 {
                record.opacity = PacketOpacity::MalformedHeaders;
                return;
            }
            record.transport_protocol = Some("tcp".into());
            record.source_port = Some(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
            record.destination_port =
                Some(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
            let header = ((bytes[offset + 12] >> 4) as usize) * 4;
            if header < 20 || bytes.len() < offset + header {
                record.opacity = PacketOpacity::MalformedHeaders;
                return;
            }
            if bytes.len() > offset + header && record.opacity != PacketOpacity::TruncatedCapture {
                record.opacity = PacketOpacity::OpaquePayload;
            }
        }
        17 => {
            if bytes.len() < offset + 8 {
                record.opacity = PacketOpacity::MalformedHeaders;
                return;
            }
            record.transport_protocol = Some("udp".into());
            record.source_port = Some(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
            record.destination_port =
                Some(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
            if bytes.len() > offset + 8 && record.opacity != PacketOpacity::TruncatedCapture {
                record.opacity = PacketOpacity::OpaquePayload;
            }
        }
        _ => {
            if record.opacity != PacketOpacity::TruncatedCapture {
                record.opacity = PacketOpacity::OpaquePayload
            }
        }
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        if index > 0 {
            out.push(':');
        }
        let _ = write!(out, "{:x}", u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    out
}
fn validate_source(value: &str) -> Result<(), NetworkImportError> {
    if value.len() < 8
        || value.len() > 128
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        Err(NetworkImportError::InvalidCaptureSource)
    } else {
        Ok(())
    }
}
fn validate_snaplen(value: u32) -> Result<(), NetworkImportError> {
    if value == 0 || value as usize > MAX_PACKET_BYTES {
        Err(NetworkImportError::InvalidSnaplen(value))
    } else {
        Ok(())
    }
}
fn validate_packet_lengths(
    captured: u32,
    original: u32,
    snaplen: u32,
) -> Result<(), NetworkImportError> {
    if captured as usize > MAX_PACKET_BYTES || captured > snaplen || captured > original {
        Err(NetworkImportError::InvalidPacketLength { captured, original, snaplen })
    } else {
        Ok(())
    }
}
fn validate_block_length(total: usize, minimum: usize) -> Result<(), NetworkImportError> {
    if total < minimum || total > MAX_BLOCK_BYTES || total % 4 != 0 {
        Err(NetworkImportError::InvalidBlockLength(total))
    } else {
        Ok(())
    }
}
fn validate_trailer<R: Read>(
    reader: &mut CountingReader<R>,
    endian: Endian,
    total: usize,
) -> Result<(), NetworkImportError> {
    let mut trailer = [0; 4];
    reader.exact(&mut trailer)?;
    if endian.u32(trailer) as usize != total {
        Err(NetworkImportError::BlockLengthMismatch)
    } else {
        Ok(())
    }
}
fn read_prefix_and_skip<R: Read>(
    reader: &mut CountingReader<R>,
    length: usize,
) -> Result<Vec<u8>, NetworkImportError> {
    let prefix_len = length.min(HEADER_PREFIX_BYTES);
    let mut prefix = vec![0; prefix_len];
    reader.exact(&mut prefix)?;
    reader.skip(length - prefix_len)?;
    Ok(prefix)
}
fn resolution_ns(units: u128) -> u64 {
    u64::try_from((1_000_000_000_u128 / units).max(1)).unwrap_or(1)
}
fn update_stats(stats: &mut ParseStats, record: &PacketRecord) -> Result<(), NetworkImportError> {
    stats.packets = stats.packets.checked_add(1).ok_or(NetworkImportError::LengthOverflow)?;
    if stats.packets > MAX_PACKETS {
        return Err(NetworkImportError::TooManyPackets(stats.packets));
    }
    stats.captured_bytes = stats
        .captured_bytes
        .checked_add(record.captured_len as u64)
        .ok_or(NetworkImportError::LengthOverflow)?;
    if record.opacity == PacketOpacity::TruncatedCapture {
        stats.truncated_packets += 1;
    }
    if !matches!(record.opacity, PacketOpacity::HeaderOnly) {
        stats.opaque_packets += 1;
    }
    Ok(())
}

fn parse_ts_resolution(options: &[u8], endian: Endian) -> Result<u128, NetworkImportError> {
    let mut offset = 0;
    let mut units = 1_000_000_u128;
    while offset + 4 <= options.len() {
        let code = endian.u16(options[offset..offset + 2].try_into().unwrap());
        let length = endian.u16(options[offset + 2..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if code == 0 {
            return Ok(units);
        }
        if offset + length > options.len() {
            return Err(NetworkImportError::MalformedOption);
        }
        if code == 9 {
            if length != 1 {
                return Err(NetworkImportError::MalformedOption);
            }
            let value = options[offset];
            units = if value & 0x80 == 0 {
                10_u128.checked_pow(value as u32).ok_or(NetworkImportError::InvalidTimestamp)?
            } else {
                2_u128
                    .checked_pow((value & 0x7f) as u32)
                    .ok_or(NetworkImportError::InvalidTimestamp)?
            };
            if units == 0 {
                return Err(NetworkImportError::InvalidTimestamp);
            }
        }
        offset += length;
        offset = (offset + 3) & !3;
    }
    if offset != options.len() {
        return Err(NetworkImportError::MalformedOption);
    }
    Ok(units)
}

#[derive(Debug, Error)]
pub enum NetworkImportError {
    #[error("input is empty")]
    EmptyInput,
    #[error("unsupported capture format or magic")]
    UnsupportedFormat,
    #[error("unsupported capture version")]
    UnsupportedVersion,
    #[error("capture source must be a bounded ASCII identifier")]
    InvalidCaptureSource,
    #[error("capture is truncated")]
    Truncated,
    #[error("length arithmetic overflow")]
    LengthOverflow,
    #[error("invalid snap length {0}")]
    InvalidSnaplen(u32),
    #[error("invalid packet lengths captured={captured} original={original} snaplen={snaplen}")]
    InvalidPacketLength { captured: u32, original: u32, snaplen: u32 },
    #[error("too many packets: {0}")]
    TooManyPackets(u64),
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid PCAPNG byte-order magic")]
    InvalidByteOrder,
    #[error("PCAPNG section is missing")]
    MissingSection,
    #[error("invalid PCAPNG block length {0}")]
    InvalidBlockLength(usize),
    #[error("PCAPNG block length trailer mismatch")]
    BlockLengthMismatch,
    #[error("PCAPNG interface block is {0} bytes, exceeding 64 KiB")]
    InterfaceBlockTooLarge(usize),
    #[error("packet references unknown interface {0}")]
    UnknownInterface(u32),
    #[error("malformed PCAPNG option")]
    MalformedOption,
    #[error("packet sink rejected record: {0}")]
    Sink(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ethernet_udp(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0; 14 + 20 + 8];
        p[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        p[14] = 0x45;
        p[16..18].copy_from_slice(&((20 + 8 + payload.len()) as u16).to_be_bytes());
        p[23] = 17;
        p[26..30].copy_from_slice(&[192, 0, 2, 1]);
        p[30..34].copy_from_slice(&[198, 51, 100, 2]);
        p[34..36].copy_from_slice(&1234_u16.to_be_bytes());
        p[36..38].copy_from_slice(&443_u16.to_be_bytes());
        p[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(payload);
        p
    }
    fn pcap(packet: &[u8], captured: u32, original: u32) -> Vec<u8> {
        let mut v = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&(65535_u32).to_le_bytes());
        v.extend_from_slice(&(1_u32).to_le_bytes());
        v.extend_from_slice(&(1_u32).to_le_bytes());
        v.extend_from_slice(&(500_000_u32).to_le_bytes());
        v.extend_from_slice(&captured.to_le_bytes());
        v.extend_from_slice(&original.to_le_bytes());
        v.extend_from_slice(&packet[..captured as usize]);
        v
    }
    fn pcapng(packet: &[u8], endian: Endian) -> Vec<u8> {
        fn put16(out: &mut Vec<u8>, value: u16, endian: Endian) {
            match endian {
                Endian::Little => out.extend_from_slice(&value.to_le_bytes()),
                Endian::Big => out.extend_from_slice(&value.to_be_bytes()),
            }
        }
        fn put32(out: &mut Vec<u8>, value: u32, endian: Endian) {
            match endian {
                Endian::Little => out.extend_from_slice(&value.to_le_bytes()),
                Endian::Big => out.extend_from_slice(&value.to_be_bytes()),
            }
        }
        fn put64(out: &mut Vec<u8>, value: i64, endian: Endian) {
            match endian {
                Endian::Little => out.extend_from_slice(&value.to_le_bytes()),
                Endian::Big => out.extend_from_slice(&value.to_be_bytes()),
            }
        }
        let mut out = vec![];
        out.extend_from_slice(&PCAPNG_SECTION);
        put32(&mut out, 28, endian);
        out.extend_from_slice(match endian {
            Endian::Little => &[0x4d, 0x3c, 0x2b, 0x1a],
            Endian::Big => &[0x1a, 0x2b, 0x3c, 0x4d],
        });
        put16(&mut out, 1, endian);
        put16(&mut out, 0, endian);
        put64(&mut out, -1, endian);
        put32(&mut out, 28, endian);
        put32(&mut out, 1, endian);
        put32(&mut out, 32, endian);
        put16(&mut out, 1, endian);
        put16(&mut out, 0, endian);
        put32(&mut out, 65535, endian);
        put16(&mut out, 9, endian);
        put16(&mut out, 1, endian);
        out.push(9);
        out.extend_from_slice(&[0; 3]);
        put16(&mut out, 0, endian);
        put16(&mut out, 0, endian);
        put32(&mut out, 32, endian);
        let padding = (4 - packet.len() % 4) % 4;
        let total = (12 + 20 + packet.len() + padding) as u32;
        put32(&mut out, 6, endian);
        put32(&mut out, total, endian);
        put32(&mut out, 0, endian);
        put32(&mut out, 0, endian);
        put32(&mut out, 1_500_000_000, endian);
        put32(&mut out, packet.len() as u32, endian);
        put32(&mut out, packet.len() as u32, endian);
        out.extend_from_slice(packet);
        out.extend(std::iter::repeat_n(0, padding));
        put32(&mut out, total, endian);
        out
    }
    #[test]
    fn parses_metadata_without_retaining_payload_or_process() {
        let packet = ethernet_udp(b"SECRET_PAYLOAD");
        let mut records = vec![];
        let stats = parse(
            &pcap(&packet, packet.len() as u32, packet.len() as u32)[..],
            "capture_001",
            |r| {
                records.push(r);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(stats.packets, 1);
        let r = &records[0];
        assert_eq!(r.destination_port, Some(443));
        assert_eq!(r.opacity, PacketOpacity::OpaquePayload);
        let encoded = serde_json::to_string(r).unwrap();
        assert!(!encoded.contains("SECRET_PAYLOAD"));
        assert!(!encoded.contains("process"));
    }
    #[test]
    fn locator_binds_source_interface_ordinal_and_byte_range() {
        let packet = ethernet_udp(&[]);
        let mut records = vec![];
        parse(&pcap(&packet, packet.len() as u32, packet.len() as u32)[..], "capture_001", |r| {
            records.push(r);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            records[0].native_locator,
            format!("pcap://capture_001/section/0/interface/0/packet/0@40+{}", packet.len())
        );
    }
    #[test]
    fn truncated_capture_is_explicit() {
        let packet = ethernet_udp(&[1; 20]);
        let cap = 42;
        let mut records = vec![];
        parse(&pcap(&packet, cap, packet.len() as u32)[..], "capture_001", |r| {
            records.push(r);
            Ok(())
        })
        .unwrap();
        assert_eq!(records[0].opacity, PacketOpacity::TruncatedCapture);
    }
    #[test]
    fn malformed_lengths_fail_closed() {
        let packet = ethernet_udp(&[]);
        let input = pcap(&packet, packet.len() as u32, packet.len() as u32 - 1);
        assert!(matches!(
            parse(&input[..], "capture_001", |_| Ok(())),
            Err(NetworkImportError::InvalidPacketLength { .. })
        ));
    }
    #[test]
    fn truncated_records_fail_closed() {
        let packet = ethernet_udp(&[]);
        let mut input = pcap(&packet, packet.len() as u32, packet.len() as u32);
        input.pop();
        assert!(matches!(
            parse(&input[..], "capture_001", |_| Ok(())),
            Err(NetworkImportError::Io(_))
        ));
    }
    #[test]
    fn unsupported_link_type_is_opaque() {
        let packet = ethernet_udp(&[]);
        let mut input = pcap(&packet, packet.len() as u32, packet.len() as u32);
        input[20..24].copy_from_slice(&999_u32.to_le_bytes());
        let mut records = vec![];
        parse(&input[..], "capture_001", |r| {
            records.push(r);
            Ok(())
        })
        .unwrap();
        assert_eq!(records[0].opacity, PacketOpacity::UnsupportedLinkType);
    }
    #[test]
    fn pcapng_little_and_big_endian_preserve_interface_time_and_locator() {
        let packet = ethernet_udp(&[]);
        for endian in [Endian::Little, Endian::Big] {
            let mut records = vec![];
            let stats = parse(&pcapng(&packet, endian)[..], "capture_001", |r| {
                records.push(r);
                Ok(())
            })
            .unwrap();
            assert_eq!(stats.packets, 1);
            assert_eq!(records[0].interface_id, 0);
            assert_eq!(records[0].timestamp_ns, 1_500_000_000);
            assert_eq!(records[0].timestamp_resolution_ns, 1);
            assert!(records[0].native_locator.contains("/section/0/interface/0/packet/0@"));
        }
    }
    #[test]
    fn pcapng_trailer_mismatch_fails_closed() {
        let packet = ethernet_udp(&[]);
        let mut input = pcapng(&packet, Endian::Little);
        let last = input.len() - 1;
        input[last] ^= 1;
        assert!(matches!(
            parse(&input[..], "capture_001", |_| Ok(())),
            Err(NetworkImportError::BlockLengthMismatch)
        ));
    }
}
