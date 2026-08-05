//! Bounded, metadata-only OTLP JSON Lines trace importer.
//!
//! The parser validates the standard OTLP JSON trace shape while retaining only
//! addressable trace/span identifiers, timing, enum state, and explicit drop
//! counts. Resource values, instrumentation details, span names, attributes,
//! events, links, status messages, and baggage are never emitted.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::io::{BufRead, Cursor, Read};
use thiserror::Error;

pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SPANS: u64 = 100_000;
const MAX_GROUPS: u64 = 100_000;
const MAX_NESTED_ITEMS: usize = 100_000;
const MAX_SHORT_STRING: usize = 512;
const MAX_VALUE_STRING: usize = 64 * 1024;
const MAX_VALUE_DEPTH: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtlpSpanRecord {
    pub line_ordinal: u64,
    pub resource_ordinal: u64,
    pub scope_ordinal: u64,
    pub span_ordinal: u64,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub start_ns: u64,
    pub end_ns: u64,
    pub kind: u32,
    pub status_code: u32,
    pub flags: u32,
    pub dropped_attributes: u32,
    pub dropped_events: u32,
    pub dropped_links: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParseStats {
    pub lines: u64,
    pub spans: u64,
}

pub fn parse<R, F>(mut input: R, source: &str, mut sink: F) -> Result<ParseStats, OtlpImportError>
where
    R: BufRead,
    F: FnMut(OtlpSpanRecord) -> Result<(), OtlpImportError>,
{
    validate_source(source)?;
    let mut stats = ParseStats::default();
    let mut total_bytes = 0_u64;
    let mut groups = 0_u64;
    loop {
        let mut line = Vec::new();
        let bytes =
            Read::take(&mut input, (MAX_LINE_BYTES + 1) as u64).read_until(b'\n', &mut line)?;
        if bytes == 0 {
            break;
        }
        if bytes > MAX_LINE_BYTES {
            return Err(OtlpImportError::LineTooLarge(bytes));
        }
        total_bytes =
            total_bytes.checked_add(bytes as u64).ok_or(OtlpImportError::FileTooLarge(u64::MAX))?;
        if total_bytes > MAX_FILE_BYTES {
            return Err(OtlpImportError::FileTooLarge(total_bytes));
        }
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        if line.is_empty() {
            return Err(OtlpImportError::EmptyLine(stats.lines + 1));
        }
        stats.lines += 1;
        let traces: RawTracesData = serde_json::from_slice(&line)?;
        for (resource_index, resource) in traces.resource_spans.into_iter().enumerate() {
            groups = groups.saturating_add(1);
            if groups > MAX_GROUPS {
                return Err(OtlpImportError::TooManyGroups(groups));
            }
            if let Some(resource) = resource.resource {
                resource.validate()?;
            }
            validate_optional_short("resource schema URL", resource.schema_url.as_deref())?;
            for (scope_index, scope) in resource.scope_spans.into_iter().enumerate() {
                groups = groups.saturating_add(1);
                if groups > MAX_GROUPS {
                    return Err(OtlpImportError::TooManyGroups(groups));
                }
                if let Some(instrumentation) = scope.scope {
                    instrumentation.validate()?;
                }
                validate_optional_short("scope schema URL", scope.schema_url.as_deref())?;
                for (span_index, span) in scope.spans.into_iter().enumerate() {
                    stats.spans += 1;
                    if stats.spans > MAX_SPANS {
                        return Err(OtlpImportError::TooManySpans(stats.spans));
                    }
                    let record = span.into_record(
                        stats.lines,
                        resource_index as u64 + 1,
                        scope_index as u64 + 1,
                        span_index as u64 + 1,
                    )?;
                    sink(record)?;
                }
            }
        }
    }
    if stats.lines == 0 {
        return Err(OtlpImportError::EmptyFile);
    }
    Ok(stats)
}

/// Parses one authenticated live OTLP trace payload. OTLP receivers must ignore
/// unknown fields, while file imports intentionally fail closed on them. This
/// projection drops only unknown keys at known trace-schema locations, then
/// runs the same bounded validators and metadata-only record projection used by
/// the hostile file importer.
pub fn parse_live_payload<F>(
    payload: &serde_json::Value,
    source: &str,
    line_ordinal: u64,
    mut sink: F,
) -> Result<ParseStats, OtlpImportError>
where
    F: FnMut(OtlpSpanRecord) -> Result<(), OtlpImportError>,
{
    let root = payload.as_object().ok_or(OtlpImportError::InvalidLivePayload)?;
    if ["resourceMetrics", "resourceLogs", "resourceProfiles"]
        .iter()
        .any(|key| root.contains_key(*key))
    {
        return Err(OtlpImportError::UnsupportedLiveSignal);
    }
    if !matches!(root.get("resourceSpans"), Some(serde_json::Value::Array(_))) {
        return Err(OtlpImportError::InvalidLivePayload);
    }
    let mut sanitized = payload.clone();
    sanitize_live_traces(&mut sanitized);
    let bytes = serde_json::to_vec(&sanitized)?;
    if bytes.len() > MAX_LINE_BYTES {
        return Err(OtlpImportError::LineTooLarge(bytes.len()));
    }
    let stats = parse(Cursor::new(bytes), source, |mut record| {
        record.line_ordinal = line_ordinal;
        sink(record)
    })?;
    if stats.lines != 1 || stats.spans == 0 {
        return Err(OtlpImportError::InvalidLivePayload);
    }
    Ok(stats)
}

fn retain_keys(value: &mut serde_json::Value, allowed: &[&str]) {
    if let Some(object) = value.as_object_mut() {
        object.retain(|key, _| allowed.contains(&key.as_str()));
    }
}

fn sanitize_array(parent: &mut serde_json::Value, key: &str, sanitize: fn(&mut serde_json::Value)) {
    if let Some(items) = parent.get_mut(key).and_then(serde_json::Value::as_array_mut) {
        for item in items {
            sanitize(item);
        }
    }
}

fn sanitize_live_traces(value: &mut serde_json::Value) {
    retain_keys(value, &["resourceSpans"]);
    sanitize_array(value, "resourceSpans", sanitize_resource_spans);
}

fn sanitize_resource_spans(value: &mut serde_json::Value) {
    retain_keys(value, &["resource", "scopeSpans", "schemaUrl"]);
    if let Some(resource) = value.get_mut("resource") {
        sanitize_resource(resource);
    }
    sanitize_array(value, "scopeSpans", sanitize_scope_spans);
}

fn sanitize_resource(value: &mut serde_json::Value) {
    retain_keys(value, &["attributes", "droppedAttributesCount"]);
    sanitize_array(value, "attributes", sanitize_key_value);
}

fn sanitize_scope_spans(value: &mut serde_json::Value) {
    retain_keys(value, &["scope", "spans", "schemaUrl"]);
    if let Some(scope) = value.get_mut("scope") {
        sanitize_scope(scope);
    }
    sanitize_array(value, "spans", sanitize_span);
}

fn sanitize_scope(value: &mut serde_json::Value) {
    retain_keys(value, &["name", "version", "attributes", "droppedAttributesCount"]);
    sanitize_array(value, "attributes", sanitize_key_value);
}

fn sanitize_span(value: &mut serde_json::Value) {
    retain_keys(
        value,
        &[
            "traceId",
            "spanId",
            "traceState",
            "parentSpanId",
            "flags",
            "name",
            "kind",
            "startTimeUnixNano",
            "endTimeUnixNano",
            "attributes",
            "droppedAttributesCount",
            "events",
            "droppedEventsCount",
            "links",
            "droppedLinksCount",
            "status",
        ],
    );
    sanitize_array(value, "attributes", sanitize_key_value);
    sanitize_array(value, "events", sanitize_event);
    sanitize_array(value, "links", sanitize_link);
    if let Some(status) = value.get_mut("status") {
        retain_keys(status, &["message", "code"]);
    }
}

fn sanitize_event(value: &mut serde_json::Value) {
    retain_keys(value, &["timeUnixNano", "name", "attributes", "droppedAttributesCount"]);
    sanitize_array(value, "attributes", sanitize_key_value);
}

fn sanitize_link(value: &mut serde_json::Value) {
    retain_keys(
        value,
        &["traceId", "spanId", "traceState", "attributes", "droppedAttributesCount", "flags"],
    );
    sanitize_array(value, "attributes", sanitize_key_value);
}

fn sanitize_key_value(value: &mut serde_json::Value) {
    retain_keys(value, &["key", "value"]);
    if let Some(any_value) = value.get_mut("value") {
        sanitize_any_value(any_value);
    }
}

fn sanitize_any_value(value: &mut serde_json::Value) {
    retain_keys(
        value,
        &[
            "stringValue",
            "boolValue",
            "intValue",
            "doubleValue",
            "arrayValue",
            "kvlistValue",
            "bytesValue",
        ],
    );
    if let Some(array) = value.get_mut("arrayValue") {
        retain_keys(array, &["values"]);
        sanitize_array(array, "values", sanitize_any_value);
    }
    if let Some(list) = value.get_mut("kvlistValue") {
        retain_keys(list, &["values"]);
        sanitize_array(list, "values", sanitize_key_value);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawTracesData {
    #[serde(default)]
    resource_spans: Vec<RawResourceSpans>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawResourceSpans {
    #[serde(default)]
    resource: Option<RawResource>,
    #[serde(default)]
    scope_spans: Vec<RawScopeSpans>,
    #[serde(default)]
    schema_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawResource {
    #[serde(default)]
    attributes: Vec<RawKeyValue>,
    #[serde(default)]
    dropped_attributes_count: u32,
}

impl RawResource {
    fn validate(self) -> Result<(), OtlpImportError> {
        let _ = self.dropped_attributes_count;
        validate_attributes(self.attributes, 0)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawScopeSpans {
    #[serde(default)]
    scope: Option<RawInstrumentationScope>,
    #[serde(default)]
    spans: Vec<RawSpan>,
    #[serde(default)]
    schema_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawInstrumentationScope {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    attributes: Vec<RawKeyValue>,
    #[serde(default)]
    dropped_attributes_count: u32,
}

impl RawInstrumentationScope {
    fn validate(self) -> Result<(), OtlpImportError> {
        let _ = self.dropped_attributes_count;
        validate_optional_short("scope name", nonempty(&self.name))?;
        validate_optional_short("scope version", nonempty(&self.version))?;
        validate_attributes(self.attributes, 0)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawSpan {
    trace_id: String,
    span_id: String,
    #[serde(default)]
    trace_state: String,
    #[serde(default)]
    parent_span_id: String,
    #[serde(default)]
    flags: u32,
    name: String,
    #[serde(default)]
    kind: u32,
    start_time_unix_nano: DecimalU64,
    end_time_unix_nano: DecimalU64,
    #[serde(default)]
    attributes: Vec<RawKeyValue>,
    #[serde(default)]
    dropped_attributes_count: u32,
    #[serde(default)]
    events: Vec<RawEvent>,
    #[serde(default)]
    dropped_events_count: u32,
    #[serde(default)]
    links: Vec<RawLink>,
    #[serde(default)]
    dropped_links_count: u32,
    #[serde(default)]
    status: Option<RawStatus>,
}

impl RawSpan {
    fn into_record(
        self,
        line_ordinal: u64,
        resource_ordinal: u64,
        scope_ordinal: u64,
        span_ordinal: u64,
    ) -> Result<OtlpSpanRecord, OtlpImportError> {
        let trace_id = validate_hex_id("trace ID", self.trace_id, 32)?;
        let span_id = validate_hex_id("span ID", self.span_id, 16)?;
        let parent_span_id = if self.parent_span_id.is_empty() {
            None
        } else {
            Some(validate_hex_id("parent span ID", self.parent_span_id, 16)?)
        };
        validate_optional_short("trace state", nonempty(&self.trace_state))?;
        validate_required_short("span name", &self.name)?;
        if self.kind > 5 {
            return Err(OtlpImportError::InvalidEnum("span kind", self.kind));
        }
        if self.start_time_unix_nano.0 == 0
            || self.end_time_unix_nano.0 < self.start_time_unix_nano.0
        {
            return Err(OtlpImportError::InvalidTimeRange);
        }
        validate_attributes(self.attributes, 0)?;
        if self.events.len() > MAX_NESTED_ITEMS || self.links.len() > MAX_NESTED_ITEMS {
            return Err(OtlpImportError::TooManyNestedItems);
        }
        for event in self.events {
            event.validate()?;
        }
        for link in self.links {
            link.validate()?;
        }
        let status_code = self.status.map(RawStatus::validate).transpose()?.unwrap_or(0);
        Ok(OtlpSpanRecord {
            line_ordinal,
            resource_ordinal,
            scope_ordinal,
            span_ordinal,
            trace_id,
            span_id,
            parent_span_id,
            start_ns: self.start_time_unix_nano.0,
            end_ns: self.end_time_unix_nano.0,
            kind: self.kind,
            status_code,
            flags: self.flags,
            dropped_attributes: self.dropped_attributes_count,
            dropped_events: self.dropped_events_count,
            dropped_links: self.dropped_links_count,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawStatus {
    #[serde(default)]
    message: String,
    #[serde(default)]
    code: u32,
}

impl RawStatus {
    fn validate(self) -> Result<u32, OtlpImportError> {
        validate_optional_value("status message", nonempty(&self.message))?;
        if self.code > 2 {
            return Err(OtlpImportError::InvalidEnum("status code", self.code));
        }
        Ok(self.code)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEvent {
    time_unix_nano: DecimalU64,
    name: String,
    #[serde(default)]
    attributes: Vec<RawKeyValue>,
    #[serde(default)]
    dropped_attributes_count: u32,
}

impl RawEvent {
    fn validate(self) -> Result<(), OtlpImportError> {
        let _ = self.dropped_attributes_count;
        if self.time_unix_nano.0 == 0 {
            return Err(OtlpImportError::InvalidTimeRange);
        }
        validate_required_short("event name", &self.name)?;
        validate_attributes(self.attributes, 0)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawLink {
    trace_id: String,
    span_id: String,
    #[serde(default)]
    trace_state: String,
    #[serde(default)]
    attributes: Vec<RawKeyValue>,
    #[serde(default)]
    dropped_attributes_count: u32,
    #[serde(default)]
    flags: u32,
}

impl RawLink {
    fn validate(self) -> Result<(), OtlpImportError> {
        let _ = (
            validate_hex_id("linked trace ID", self.trace_id, 32)?,
            validate_hex_id("linked span ID", self.span_id, 16)?,
            self.dropped_attributes_count,
            self.flags,
        );
        validate_optional_short("linked trace state", nonempty(&self.trace_state))?;
        validate_attributes(self.attributes, 0)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyValue {
    key: String,
    value: RawAnyValue,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawAnyValue {
    #[serde(default)]
    string_value: Option<String>,
    #[serde(default)]
    bool_value: Option<bool>,
    #[serde(default)]
    int_value: Option<DecimalI64>,
    #[serde(default)]
    double_value: Option<f64>,
    #[serde(default)]
    array_value: Option<RawArrayValue>,
    #[serde(default)]
    kvlist_value: Option<RawKeyValueList>,
    #[serde(default)]
    bytes_value: Option<String>,
}

impl RawAnyValue {
    fn validate(self, depth: usize) -> Result<(), OtlpImportError> {
        if depth > MAX_VALUE_DEPTH {
            return Err(OtlpImportError::ValueNestingTooDeep);
        }
        let variants = [
            self.string_value.is_some(),
            self.bool_value.is_some(),
            self.int_value.is_some(),
            self.double_value.is_some(),
            self.array_value.is_some(),
            self.kvlist_value.is_some(),
            self.bytes_value.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if variants != 1 {
            return Err(OtlpImportError::InvalidAnyValue);
        }
        if let Some(value) = self.string_value.as_deref() {
            validate_optional_value("attribute string", Some(value))?;
        }
        if self.double_value.is_some_and(|value| !value.is_finite()) {
            return Err(OtlpImportError::InvalidAnyValue);
        }
        if let Some(value) = self.int_value {
            let _ = value.0;
        }
        if let Some(array) = self.array_value {
            if array.values.len() > MAX_NESTED_ITEMS {
                return Err(OtlpImportError::TooManyNestedItems);
            }
            for value in array.values {
                value.validate(depth + 1)?;
            }
        }
        if let Some(list) = self.kvlist_value {
            validate_attributes(list.values, depth + 1)?;
        }
        if let Some(value) = self.bytes_value.as_deref() {
            validate_base64_shape(value)?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArrayValue {
    #[serde(default)]
    values: Vec<RawAnyValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyValueList {
    #[serde(default)]
    values: Vec<RawKeyValue>,
}

fn validate_attributes(values: Vec<RawKeyValue>, depth: usize) -> Result<(), OtlpImportError> {
    if values.len() > MAX_NESTED_ITEMS {
        return Err(OtlpImportError::TooManyNestedItems);
    }
    for item in values {
        validate_required_short("attribute key", &item.key)?;
        item.value.validate(depth)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DecimalU64(u64);

impl<'de> Deserialize<'de> for DecimalU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DecimalVisitor;
        impl<'de> Visitor<'de> for DecimalVisitor {
            type Value = DecimalU64;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an unsigned 64-bit integer or decimal string")
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(DecimalU64(value))
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map(DecimalU64).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(DecimalVisitor)
    }
}

#[derive(Clone, Copy)]
struct DecimalI64(i64);

impl<'de> Deserialize<'de> for DecimalI64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DecimalVisitor;
        impl<'de> Visitor<'de> for DecimalVisitor {
            type Value = DecimalI64;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a signed 64-bit integer or decimal string")
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(DecimalI64(value))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                i64::try_from(value).map(DecimalI64).map_err(E::custom)
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map(DecimalI64).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(DecimalVisitor)
    }
}

fn validate_hex_id(
    field: &'static str,
    value: String,
    length: usize,
) -> Result<String, OtlpImportError> {
    if value.len() != length
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(OtlpImportError::InvalidIdentifier(field));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_base64_shape(value: &str) -> Result<(), OtlpImportError> {
    let padding = value.bytes().rev().take_while(|byte| *byte == b'=').count();
    if value.len() > MAX_VALUE_STRING
        || value.len() % 4 != 0
        || padding > 2
        || value[..value.len().saturating_sub(padding)].contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(OtlpImportError::InvalidAnyValue);
    }
    Ok(())
}

fn validate_source(source: &str) -> Result<(), OtlpImportError> {
    if source.is_empty()
        || source.len() > 128
        || !source.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(OtlpImportError::InvalidSource);
    }
    Ok(())
}

fn validate_required_short(field: &'static str, value: &str) -> Result<(), OtlpImportError> {
    if value.is_empty() || value.len() > MAX_SHORT_STRING || value.chars().any(char::is_control) {
        return Err(OtlpImportError::InvalidShortField(field));
    }
    Ok(())
}

fn validate_optional_short(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), OtlpImportError> {
    if let Some(value) = value {
        validate_required_short(field, value)?;
    }
    Ok(())
}

fn validate_optional_value(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), OtlpImportError> {
    if value
        .is_some_and(|value| value.len() > MAX_VALUE_STRING || value.chars().any(char::is_control))
    {
        return Err(OtlpImportError::InvalidValueField(field));
    }
    Ok(())
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

#[derive(Debug, Error)]
pub enum OtlpImportError {
    #[error("OTLP file is empty")]
    EmptyFile,
    #[error("OTLP JSONL line {0} is empty")]
    EmptyLine(u64),
    #[error("OTLP JSONL line is {0} bytes, exceeding the 16 MiB record limit")]
    LineTooLarge(usize),
    #[error("OTLP input is {0} bytes, exceeding the 4 GiB file limit")]
    FileTooLarge(u64),
    #[error("OTLP source identifier is invalid")]
    InvalidSource,
    #[error("live OTLP payload is not one nonempty trace request")]
    InvalidLivePayload,
    #[error("live OTLP payload contains a non-trace signal")]
    UnsupportedLiveSignal,
    #[error("OTLP group count exceeds the limit: {0}")]
    TooManyGroups(u64),
    #[error("OTLP span count exceeds the limit: {0}")]
    TooManySpans(u64),
    #[error("OTLP nested collection exceeds the limit")]
    TooManyNestedItems,
    #[error("OTLP value nesting exceeds the limit")]
    ValueNestingTooDeep,
    #[error("OTLP {0} is not a valid nonzero hex identifier")]
    InvalidIdentifier(&'static str),
    #[error("OTLP {0} is empty, oversized, or contains control characters")]
    InvalidShortField(&'static str),
    #[error("OTLP {0} is oversized or contains control characters")]
    InvalidValueField(&'static str),
    #[error("OTLP time range is zero or inverted")]
    InvalidTimeRange,
    #[error("OTLP {0} enum value is invalid: {1}")]
    InvalidEnum(&'static str, u32),
    #[error("OTLP AnyValue must contain exactly one valid bounded value")]
    InvalidAnyValue,
    #[error("OTLP sink rejected a record: {0}")]
    Sink(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const VALID: &str = r#"{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"seed-resource"}}]},"scopeSpans":[{"scope":{"name":"seed-scope"},"spans":[{"traceId":"5B8EFFF798038103D269B633813FC60C","spanId":"0102040800000001","parentSpanId":"0102040800000000","name":"seed-span-name","kind":2,"startTimeUnixNano":"1581452772000000321","endTimeUnixNano":"1581452773000000789","attributes":[{"key":"http.url","value":{"stringValue":"https://seed-host/private?seed-query"}}],"droppedAttributesCount":1,"events":[{"timeUnixNano":"1581452772500000000","name":"seed-event","attributes":[]}],"droppedEventsCount":2,"links":[],"droppedLinksCount":3,"status":{"message":"seed-status","code":2}}]}]}]}"#;

    #[test]
    fn parses_standard_trace_jsonl_and_emits_metadata_only() {
        let mut records = Vec::new();
        let stats = parse(Cursor::new(format!("{VALID}\n")), "selected_otlp", |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(stats, ParseStats { lines: 1, spans: 1 });
        assert_eq!(records[0].trace_id, "5b8efff798038103d269b633813fc60c");
        assert_eq!(records[0].status_code, 2);
        let emitted = format!("{:?}", records);
        for secret in [
            "seed-resource",
            "seed-scope",
            "seed-span-name",
            "seed-host",
            "seed-event",
            "seed-status",
        ] {
            assert!(!emitted.contains(secret));
        }
    }

    #[test]
    fn rejects_unknown_fields_mixed_signal_and_invalid_ranges() {
        let unknown = VALID.replace("\"kind\":2", "\"kind\":2,\"surprise\":true");
        assert!(parse(Cursor::new(unknown), "selected_otlp", |_| Ok(())).is_err());
        let mixed = r#"{"resourceMetrics":[]}"#;
        assert!(parse(Cursor::new(mixed), "selected_otlp", |_| Ok(())).is_err());
        let inverted = VALID.replace("1581452773000000789", "1");
        assert!(matches!(
            parse(Cursor::new(inverted), "selected_otlp", |_| Ok(())),
            Err(OtlpImportError::InvalidTimeRange)
        ));
    }

    #[test]
    fn live_receiver_ignores_unknown_fields_but_preserves_strict_validation() {
        let mut payload: serde_json::Value = serde_json::from_str(VALID).unwrap();
        payload["futureTopLevel"] = serde_json::json!({"secret": "drop-me"});
        payload["resourceSpans"][0]["futureResourceGroup"] = true.into();
        payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["futureSpanField"] =
            "ignored".into();
        payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"][0]["value"]
            ["futureAnyValueField"] = "ignored".into();
        let mut records = Vec::new();
        let stats = parse_live_payload(&payload, "live_source_001", 41, |record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
        assert_eq!(stats.spans, 1);
        assert_eq!(records[0].line_ordinal, 41);
        assert!(!format!("{records:?}").contains("drop-me"));

        let mixed = serde_json::json!({"resourceSpans": [], "resourceMetrics": []});
        assert!(matches!(
            parse_live_payload(&mixed, "live_source_001", 1, |_| Ok(())),
            Err(OtlpImportError::UnsupportedLiveSignal)
        ));
        let empty = serde_json::json!({"resourceSpans": []});
        assert!(matches!(
            parse_live_payload(&empty, "live_source_001", 1, |_| Ok(())),
            Err(OtlpImportError::InvalidLivePayload)
        ));
        let invalid = serde_json::json!({"resourceSpans": [{"scopeSpans": [{"spans": [{"traceId": "bad"}]}]}]});
        assert!(parse_live_payload(&invalid, "live_source_001", 1, |_| Ok(())).is_err());
    }
}
