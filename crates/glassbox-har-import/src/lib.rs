//! Streaming, metadata-only HAR 1.2 parser.
//!
//! Entries are decoded one at a time. Credentials, headers, cookies, query
//! values, request bodies, response bodies, hosts, paths, and server addresses
//! are consumed but never retained in output records.

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::fmt;
use std::io::{Read, Take};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;

pub const MAX_HAR_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ENTRIES: u64 = 100_000;
const MAX_SHORT_STRING: usize = 256;
const MAX_URL_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: i64 = 16 * 1024 * 1024 * 1024;
const MAX_DURATION_MS: f64 = 24.0 * 60.0 * 60.0 * 1_000.0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HarRecord {
    pub ordinal: u64,
    pub started_ns: i128,
    pub duration_ns: u64,
    pub method: String,
    pub structured_url: String,
    pub status: u16,
    pub body_size: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParseStats {
    pub entries: u64,
}

struct CountingReader<R> {
    inner: Take<R>,
    bytes_read: u64,
}

impl<R: Read> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner: inner.take(MAX_HAR_BYTES + 1), bytes_read: 0 }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes_read = self.bytes_read.saturating_add(read as u64);
        Ok(read)
    }
}

pub fn parse<R, F>(reader: R, source: &str, mut sink: F) -> Result<ParseStats, HarImportError>
where
    R: Read,
    F: FnMut(HarRecord) -> Result<(), HarImportError>,
{
    validate_source(source)?;
    let mut reader = CountingReader::new(reader);
    let mut processing_error = None;
    let parsed = {
        let mut deserializer = serde_json::Deserializer::from_reader(&mut reader);
        let parsed = RootSeed { sink: &mut sink, processing_error: &mut processing_error }
            .deserialize(&mut deserializer);
        parsed.and_then(|stats| {
            deserializer.end()?;
            Ok(stats)
        })
    };
    if reader.bytes_read > MAX_HAR_BYTES {
        return Err(HarImportError::InputTooLarge(reader.bytes_read));
    }
    if let Some(error) = processing_error {
        return Err(error);
    }
    parsed.map_err(HarImportError::Json)
}

struct RootSeed<'a, F> {
    sink: &'a mut F,
    processing_error: &'a mut Option<HarImportError>,
}

impl<'de, F> DeserializeSeed<'de> for RootSeed<'_, F>
where
    F: FnMut(HarRecord) -> Result<(), HarImportError>,
{
    type Value = ParseStats;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(RootVisitor {
            sink: self.sink,
            processing_error: self.processing_error,
        })
    }
}

struct RootVisitor<'a, F> {
    sink: &'a mut F,
    processing_error: &'a mut Option<HarImportError>,
}

impl<'de, F> Visitor<'de> for RootVisitor<'_, F>
where
    F: FnMut(HarRecord) -> Result<(), HarImportError>,
{
    type Value = ParseStats;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a HAR object containing exactly one log")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "log" if result.is_none() => {
                    result = Some(map.next_value_seed(LogSeed {
                        sink: self.sink,
                        processing_error: self.processing_error,
                    })?);
                }
                "log" => return Err(de::Error::duplicate_field("log")),
                _ => return Err(de::Error::unknown_field(&key, &["log"])),
            }
        }
        result.ok_or_else(|| de::Error::missing_field("log"))
    }
}

struct LogSeed<'a, F> {
    sink: &'a mut F,
    processing_error: &'a mut Option<HarImportError>,
}

impl<'de, F> DeserializeSeed<'de> for LogSeed<'_, F>
where
    F: FnMut(HarRecord) -> Result<(), HarImportError>,
{
    type Value = ParseStats;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(LogVisitor {
            sink: self.sink,
            processing_error: self.processing_error,
        })
    }
}

struct LogVisitor<'a, F> {
    sink: &'a mut F,
    processing_error: &'a mut Option<HarImportError>,
}

impl<'de, F> Visitor<'de> for LogVisitor<'_, F>
where
    F: FnMut(HarRecord) -> Result<(), HarImportError>,
{
    type Value = ParseStats;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a HAR 1.2 log object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut version = None;
        let mut creator = false;
        let mut entries = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "version" if version.is_none() => version = Some(map.next_value::<String>()?),
                "version" => return Err(de::Error::duplicate_field("version")),
                "creator" if !creator => {
                    map.next_value::<IgnoredAny>()?;
                    creator = true;
                }
                "creator" => return Err(de::Error::duplicate_field("creator")),
                "entries" if entries.is_none() => {
                    entries = Some(map.next_value_seed(EntriesSeed {
                        sink: self.sink,
                        processing_error: self.processing_error,
                    })?);
                }
                "entries" => return Err(de::Error::duplicate_field("entries")),
                "browser" | "pages" | "comment" => {
                    map.next_value::<IgnoredAny>()?;
                }
                _ => {
                    return Err(de::Error::unknown_field(
                        &key,
                        &["version", "creator", "browser", "pages", "entries", "comment"],
                    ));
                }
            }
        }
        if version.as_deref() != Some("1.2") {
            return Err(de::Error::custom("only HAR version 1.2 is supported"));
        }
        if !creator {
            return Err(de::Error::missing_field("creator"));
        }
        entries.ok_or_else(|| de::Error::missing_field("entries"))
    }
}

struct EntriesSeed<'a, F> {
    sink: &'a mut F,
    processing_error: &'a mut Option<HarImportError>,
}

impl<'de, F> DeserializeSeed<'de> for EntriesSeed<'_, F>
where
    F: FnMut(HarRecord) -> Result<(), HarImportError>,
{
    type Value = ParseStats;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(EntriesVisitor {
            sink: self.sink,
            processing_error: self.processing_error,
        })
    }
}

struct EntriesVisitor<'a, F> {
    sink: &'a mut F,
    processing_error: &'a mut Option<HarImportError>,
}

impl<'de, F> Visitor<'de> for EntriesVisitor<'_, F>
where
    F: FnMut(HarRecord) -> Result<(), HarImportError>,
{
    type Value = ParseStats;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded array of HAR entries")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut entries = 0_u64;
        while let Some(raw) = sequence.next_element::<RawEntry>()? {
            entries += 1;
            if entries > MAX_ENTRIES {
                return Err(de::Error::custom("HAR entry count exceeds the format limit"));
            }
            let record = match raw.into_record(entries) {
                Ok(record) => record,
                Err(error) => {
                    *self.processing_error = Some(error);
                    return Err(de::Error::custom("HAR record validation failed"));
                }
            };
            if let Err(error) = (self.sink)(record) {
                *self.processing_error = Some(error);
                return Err(de::Error::custom("HAR sink rejected the record"));
            }
        }
        Ok(ParseStats { entries })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEntry {
    #[serde(default)]
    pageref: Option<IgnoredAny>,
    started_date_time: String,
    time: f64,
    request: RawRequest,
    response: RawResponse,
    cache: IgnoredAny,
    timings: RawTimings,
    #[serde(default, rename = "serverIPAddress")]
    server_ip_address: Option<IgnoredAny>,
    #[serde(default)]
    connection: Option<IgnoredAny>,
    #[serde(default)]
    comment: Option<IgnoredAny>,
    #[serde(default, rename = "_fetchType")]
    apple_fetch_type: Option<IgnoredAny>,
    #[serde(default, rename = "_precisionPreservingTimings")]
    apple_precision_timings: Option<IgnoredAny>,
    #[serde(default, rename = "_sourceApplicationBundleIdentifier")]
    apple_source_bundle: Option<IgnoredAny>,
    #[serde(default, rename = "_taskUUID")]
    apple_task_uuid: Option<IgnoredAny>,
    #[serde(default, rename = "_transactionUUID")]
    apple_transaction_uuid: Option<IgnoredAny>,
}

impl RawEntry {
    fn into_record(self, ordinal: u64) -> Result<HarRecord, HarImportError> {
        let _ = (
            self.pageref,
            self.cache,
            self.server_ip_address,
            self.connection,
            self.comment,
            self.apple_fetch_type,
            self.apple_precision_timings,
            self.apple_source_bundle,
            self.apple_task_uuid,
            self.apple_transaction_uuid,
        );
        validate_short("method", &self.request.method)?;
        validate_short("request HTTP version", &self.request.http_version)?;
        validate_short("response status text", &self.response.status_text)?;
        validate_short("response HTTP version", &self.response.http_version)?;
        self.timings.validate()?;
        self.request.validate_sizes()?;
        self.response.validate_sizes()?;
        let started = OffsetDateTime::parse(&self.started_date_time, &Rfc3339)
            .map_err(|_| HarImportError::InvalidTimestamp)?;
        if !self.time.is_finite() || !(0.0..=MAX_DURATION_MS).contains(&self.time) {
            return Err(HarImportError::InvalidDuration);
        }
        let duration_ns = (self.time * 1_000_000.0).round() as u64;
        let body_size = self.response.body_size_value()?;
        Ok(HarRecord {
            ordinal,
            started_ns: started.unix_timestamp_nanos(),
            duration_ns,
            method: self.request.method,
            structured_url: structured_url(&self.request.url)?,
            status: self.response.status,
            body_size,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRequest {
    method: String,
    url: String,
    http_version: String,
    cookies: IgnoredAny,
    headers: IgnoredAny,
    query_string: IgnoredAny,
    #[serde(default)]
    post_data: Option<IgnoredAny>,
    headers_size: i64,
    body_size: i64,
    #[serde(default)]
    comment: Option<IgnoredAny>,
}

impl RawRequest {
    fn validate_sizes(&self) -> Result<(), HarImportError> {
        let _ = (&self.cookies, &self.headers, &self.query_string, &self.post_data, &self.comment);
        validate_size(self.headers_size)?;
        validate_size(self.body_size)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawResponse {
    status: u16,
    status_text: String,
    http_version: String,
    cookies: IgnoredAny,
    headers: IgnoredAny,
    content: RawContent,
    #[serde(rename = "redirectURL")]
    redirect_url: IgnoredAny,
    headers_size: i64,
    body_size: i64,
    #[serde(default)]
    comment: Option<IgnoredAny>,
}

impl RawResponse {
    fn validate_sizes(&self) -> Result<(), HarImportError> {
        let _ = (&self.cookies, &self.headers, &self.redirect_url, &self.comment);
        validate_size(self.headers_size)?;
        validate_size(self.body_size)?;
        self.content.validate()
    }

    fn body_size_value(&self) -> Result<Option<u64>, HarImportError> {
        if self.body_size >= 0 {
            return Ok(Some(self.body_size as u64));
        }
        if self.content.size >= 0 {
            return Ok(Some(self.content.size as u64));
        }
        Ok(None)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawContent {
    size: i64,
    #[serde(default)]
    compression: Option<i64>,
    mime_type: String,
    #[serde(default)]
    text: Option<IgnoredAny>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    comment: Option<IgnoredAny>,
}

impl RawContent {
    fn validate(&self) -> Result<(), HarImportError> {
        let _ = (&self.text, &self.comment);
        validate_size(self.size)?;
        if let Some(compression) = self.compression {
            validate_size(compression)?;
        }
        validate_short("MIME type", &self.mime_type)?;
        if let Some(encoding) = &self.encoding {
            validate_short("content encoding", encoding)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTimings {
    #[serde(default)]
    blocked: Option<f64>,
    #[serde(default)]
    dns: Option<f64>,
    #[serde(default)]
    connect: Option<f64>,
    send: f64,
    wait: f64,
    receive: f64,
    #[serde(default)]
    ssl: Option<f64>,
    #[serde(default)]
    comment: Option<IgnoredAny>,
}

impl RawTimings {
    fn validate(&self) -> Result<(), HarImportError> {
        let _ = &self.comment;
        for value in [
            self.blocked,
            self.dns,
            self.connect,
            Some(self.send),
            Some(self.wait),
            Some(self.receive),
            self.ssl,
        ]
        .into_iter()
        .flatten()
        {
            if !value.is_finite() || !(-1.0..=MAX_DURATION_MS).contains(&value) {
                return Err(HarImportError::InvalidTiming);
            }
        }
        Ok(())
    }
}

fn structured_url(raw: &str) -> Result<String, HarImportError> {
    if raw.len() > MAX_URL_BYTES {
        return Err(HarImportError::UrlTooLarge(raw.len()));
    }
    let url = Url::parse(raw).map_err(|_| HarImportError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(HarImportError::InvalidUrl);
    }
    let query_keys = url.query_pairs().count();
    if query_keys > 10_000 {
        return Err(HarImportError::TooManyQueryParameters(query_keys));
    }
    let port = url.port().map(|value| format!(":{value}")).unwrap_or_default();
    let query = if query_keys == 0 { String::new() } else { format!("?keys={query_keys}") };
    Ok(format!("{}://[redacted]{port}/[redacted]{query}", url.scheme()))
}

fn validate_source(source: &str) -> Result<(), HarImportError> {
    if source.is_empty()
        || source.len() > 128
        || !source.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(HarImportError::InvalidSource);
    }
    Ok(())
}

fn validate_short(field: &'static str, value: &str) -> Result<(), HarImportError> {
    if value.is_empty() || value.len() > MAX_SHORT_STRING || value.chars().any(char::is_control) {
        return Err(HarImportError::InvalidShortField(field));
    }
    Ok(())
}

fn validate_size(value: i64) -> Result<(), HarImportError> {
    if !(-1..=MAX_BODY_BYTES).contains(&value) {
        return Err(HarImportError::InvalidSize(value));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum HarImportError {
    #[error("HAR input is {0} bytes, exceeding the 16 MiB format limit")]
    InputTooLarge(u64),
    #[error("HAR source identifier is invalid")]
    InvalidSource,
    #[error("HAR timestamp is not valid RFC 3339")]
    InvalidTimestamp,
    #[error("HAR duration is invalid or exceeds 24 hours")]
    InvalidDuration,
    #[error("HAR timing value is invalid")]
    InvalidTiming,
    #[error("HAR URL is invalid or uses an unsupported scheme")]
    InvalidUrl,
    #[error("HAR URL is {0} bytes, exceeding the 64 KiB field limit")]
    UrlTooLarge(usize),
    #[error("HAR URL contains too many query parameters: {0}")]
    TooManyQueryParameters(usize),
    #[error("HAR {0} field is empty, oversized, or contains control characters")]
    InvalidShortField(&'static str),
    #[error("HAR size value is invalid: {0}")]
    InvalidSize(i64),
    #[error("HAR sink rejected a record: {0}")]
    Sink(String),
    #[error(transparent)]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    const VALID: &str = r#"{"log":{"version":"1.2","creator":{},"entries":[{"startedDateTime":"2026-07-13T21:00:00.123Z","time":12.5,"request":{"method":"GET","url":"https://alice:pw@secret.example/private?q=secret&token=hidden","httpVersion":"HTTP/2","cookies":[{"name":"sid","value":"secret"}],"headers":[{"name":"Authorization","value":"Bearer secret"}],"queryString":[{"name":"q","value":"secret"}],"headersSize":120,"bodySize":0},"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/2","cookies":[],"headers":[],"content":{"size":42,"mimeType":"application/json","text":"secret response"},"redirectURL":"","headersSize":80,"bodySize":42},"cache":{},"timings":{"send":1,"wait":10,"receive":1.5}}]}}"#;

    #[test]
    fn streams_metadata_and_drops_sensitive_har_content() {
        let mut records = Vec::new();
        let stats = parse(Cursor::new(VALID), "selected_har", |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(stats.entries, 1);
        assert_eq!(records[0].structured_url, "https://[redacted]/[redacted]?keys=2");
        let debug = format!("{records:?}");
        assert!(!debug.contains("secret.example"));
        assert!(!debug.contains("Bearer secret"));
        assert!(!debug.contains("secret response"));
    }

    #[test]
    fn rejects_unknown_schema_invalid_time_and_oversized_input() {
        let unknown = VALID.replace("\"time\":12.5", "\"time\":12.5,\"_initiator\":{}");
        assert!(parse(Cursor::new(unknown), "selected_har", |_| Ok(())).is_err());
        let invalid_time = VALID.replace("12.5", "-2");
        let invalid_time_result = parse(Cursor::new(invalid_time), "selected_har", |_| Ok(()));
        assert!(
            matches!(invalid_time_result, Err(HarImportError::InvalidDuration)),
            "unexpected result: {invalid_time_result:?}"
        );
        let prefix = std::io::repeat(b' ').take(MAX_HAR_BYTES + 1);
        assert!(matches!(
            parse(prefix, "selected_har", |_| Ok(())),
            Err(HarImportError::InputTooLarge(_))
        ));
    }

    #[test]
    fn accepts_the_gate_corpus_with_standard_har_acronym_fields() {
        let corpus = include_str!("../../glassbox-fixtures/corpus/hostile-import/har/valid.har");
        let mut records = Vec::new();
        let stats = parse(Cursor::new(corpus), "selected_har", |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(stats.entries, 1);
        assert_eq!(records[0].structured_url, "https://[redacted]/[redacted]?keys=2");
        assert!(!format!("{records:?}").contains("203.0.113.9"));
    }

    #[test]
    fn accepts_only_the_reviewed_apple_instruments_extensions() {
        let apple = VALID.replace(
            "\"time\":12.5",
            "\"time\":12.5,\"_fetchType\":\"network\",\"_precisionPreservingTimings\":{},\"_sourceApplicationBundleIdentifier\":null,\"_taskUUID\":\"fixture-task\",\"_transactionUUID\":\"fixture-transaction\"",
        );
        let stats = parse(Cursor::new(apple), "instruments_har", |_| Ok(())).unwrap();
        assert_eq!(stats.entries, 1);
        let unknown = VALID.replace("\"time\":12.5", "\"time\":12.5,\"_appleUnknown\":true");
        assert!(parse(Cursor::new(unknown), "instruments_har", |_| Ok(())).is_err());
    }
}
