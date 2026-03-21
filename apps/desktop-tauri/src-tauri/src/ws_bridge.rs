use crate::control_plane::{
    build_list_tabs_command, build_set_ui_capture_command, build_start_capture_command,
    build_stop_capture_command, correlation_id_of, event_matches_pending, from_json_text,
    parse_error_payload, parse_hello_payload, parse_session_ended_payload,
    parse_session_started_payload, parse_tabs_payload, to_json_text, EVT_ERROR, EVT_HELLO,
    EVT_RAW_EVENT, EVT_SESSION_ENDED, EVT_SESSION_STARTED,
};
use crate::{DesktopIngestService, PairingContext};
use dtt_core::{
    EvtErrorPayload, EvtHelloPayload, EvtPairingDiscoveredPayload, EvtSessionEndedPayload,
    EvtSessionStartedPayload, JsonEnvelope, PairingUxStateV1, RedactionLevel,
    ReliabilityMetricKeyV1, TabDescriptorV1, ENVELOPE_VERSION,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::{self, http::StatusCode, Message};
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};

const COMMAND_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeDiagnostic {
    pub ts_ms: i64,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Error, Clone)]
pub enum BridgeError {
    #[error("websocket bridge is disconnected")]
    WsDisconnected,
    #[error("command timed out")]
    Timeout,
    #[error("command channel closed")]
    ChannelClosed,
    #[error("invalid response payload: {0}")]
    InvalidResponse(String),
    #[error("extension error: {0}")]
    ExtensionError(String),
    #[error("io error: {0}")]
    Io(String),
}

struct PendingRequest {
    expected_type: String,
    tx: mpsc::Sender<Result<JsonEnvelope, BridgeError>>,
}

enum RuntimeCommand {
    Send {
        envelope: Box<JsonEnvelope>,
        expected_type: String,
        tx: mpsc::Sender<Result<JsonEnvelope, BridgeError>>,
    },
    Stop,
}

enum RuntimeEvent {
    Connected { connection_id: u64, writer_tx: UnboundedSender<JsonEnvelope> },
    Incoming { connection_id: u64, envelope: Box<JsonEnvelope> },
    Closed { connection_id: u64 },
}

enum AcceptedSocket {
    Authenticated(WebSocketStream<tokio::net::TcpStream>),
    Discovery {
        ws: WebSocketStream<tokio::net::TcpStream>,
        device_id: String,
        browser_label: String,
    },
}

#[derive(Debug, Clone)]
enum AcceptMode {
    Authenticated,
    Discovery { device_id: String, browser_label: String },
}

pub struct CaptureBridgeHandle {
    context: PairingContext,
    token: String,
    command_tx: UnboundedSender<RuntimeCommand>,
    diagnostics: Arc<Mutex<Vec<BridgeDiagnostic>>>,
    connected: Arc<AtomicBool>,
    ingest_service: Arc<Mutex<DesktopIngestService>>,
    request_counter: AtomicU64,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl CaptureBridgeHandle {
    #[must_use]
    pub fn context(&self) -> &PairingContext {
        &self.context
    }

    pub fn diagnostics(&self) -> Vec<BridgeDiagnostic> {
        self.diagnostics.lock().map(|guard| guard.clone()).unwrap_or_default()
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn wait_until_connected(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.is_connected() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.is_connected()
    }

    pub fn list_tabs(&self) -> Result<Vec<TabDescriptorV1>, BridgeError> {
        let envelope =
            build_list_tabs_command(now_ms(), self.next_request_id(), self.token.clone());
        let response = self.send_and_wait(envelope, "evt.tabs_list")?;
        if response.envelope_type == EVT_ERROR {
            return Err(BridgeError::ExtensionError(parse_error_message(&response)));
        }
        let parsed = parse_tabs_payload(&response)
            .map_err(|error| BridgeError::InvalidResponse(error.to_string()))?;
        Ok(parsed.tabs)
    }

    pub fn start_capture(
        &self,
        tab_id: i64,
        privacy_mode: RedactionLevel,
        session_id: &str,
    ) -> Result<EvtSessionStartedPayload, BridgeError> {
        let envelope = build_start_capture_command(
            now_ms(),
            self.next_request_id(),
            self.token.clone(),
            tab_id,
            privacy_mode,
            session_id.to_string(),
        );
        let response = self.send_and_wait(envelope, EVT_SESSION_STARTED)?;
        if response.envelope_type == EVT_ERROR {
            return Err(BridgeError::ExtensionError(parse_error_message(&response)));
        }
        parse_session_started_payload(&response)
            .map_err(|error| BridgeError::InvalidResponse(error.to_string()))
    }

    pub fn stop_capture(&self, session_id: &str) -> Result<EvtSessionEndedPayload, BridgeError> {
        let envelope = build_stop_capture_command(
            now_ms(),
            self.next_request_id(),
            self.token.clone(),
            session_id.to_string(),
        );
        let response = self.send_and_wait(envelope, EVT_SESSION_ENDED)?;
        if response.envelope_type == EVT_ERROR {
            return Err(BridgeError::ExtensionError(parse_error_message(&response)));
        }
        parse_session_ended_payload(&response)
            .map_err(|error| BridgeError::InvalidResponse(error.to_string()))
    }

    pub fn set_ui_capture(&self, enabled: bool) -> Result<EvtHelloPayload, BridgeError> {
        let envelope = build_set_ui_capture_command(
            now_ms(),
            self.next_request_id(),
            self.token.clone(),
            enabled,
        );
        let response = self.send_and_wait(envelope, EVT_HELLO)?;
        if response.envelope_type == EVT_ERROR {
            return Err(BridgeError::ExtensionError(parse_error_message(&response)));
        }
        parse_hello_payload(&response)
            .map_err(|error| BridgeError::InvalidResponse(error.to_string()))
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn next_request_id(&self) -> String {
        let next = self.request_counter.fetch_add(1, Ordering::Relaxed) + 1;
        format!("req_{next}")
    }

    fn send_and_wait(
        &self,
        envelope: JsonEnvelope,
        expected_type: &str,
    ) -> Result<JsonEnvelope, BridgeError> {
        let (tx, rx) = mpsc::channel();
        self.command_tx
            .send(RuntimeCommand::Send {
                envelope: Box::new(envelope),
                expected_type: expected_type.to_string(),
                tx,
            })
            .map_err(|_| BridgeError::ChannelClosed)?;

        let recv_result = rx.recv_timeout(Duration::from_millis(COMMAND_TIMEOUT_MS));
        match recv_result {
            Ok(Ok(envelope)) => Ok(envelope),
            Ok(Err(error)) => Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                emit_metric(
                    &self.ingest_service,
                    None,
                    ReliabilityMetricKeyV1::CommandTimeoutCount,
                    now_ms(),
                    "ws_bridge",
                    json!({"stage": "send_and_wait"}),
                );
                Err(BridgeError::Timeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(BridgeError::ChannelClosed),
        }
    }

    #[must_use]
    pub fn storage_session_count(&self) -> usize {
        self.ingest_service.lock().map(|service| service.storage().session_count()).unwrap_or(0)
    }

    #[must_use]
    pub fn storage_events_raw_count(&self) -> usize {
        self.ingest_service.lock().map(|service| service.storage().events_raw_count()).unwrap_or(0)
    }

    #[must_use]
    pub fn storage_session_ended_at_ms(&self, session_id: &str) -> Option<i64> {
        self.ingest_service
            .lock()
            .ok()
            .and_then(|service| service.storage().session_ended_at_ms(session_id))
    }
}

impl Drop for CaptureBridgeHandle {
    fn drop(&mut self) {
        let _ = self.command_tx.send(RuntimeCommand::Stop);
        if let Some(join_handle) = self.join_handle.take() {
            let _ = join_handle.join();
        }
    }
}

pub fn start_ws_bridge(
    context: PairingContext,
    ingest_service: DesktopIngestService,
) -> Result<CaptureBridgeHandle, BridgeError> {
    let diagnostics = Arc::new(Mutex::new(Vec::new()));
    let connected = Arc::new(AtomicBool::new(false));
    let ingest_service = Arc::new(Mutex::new(ingest_service));
    let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::channel();

    let diagnostics_clone = Arc::clone(&diagnostics);
    let connected_clone = Arc::clone(&connected);
    let ingest_clone = Arc::clone(&ingest_service);
    let context_clone = context.clone();

    let join_handle = thread::spawn(move || {
        let runtime = Runtime::new().expect("create ws runtime");
        runtime.block_on(async move {
            let ingest_for_error = Arc::clone(&ingest_clone);
            if let Err(error) = run_ws_runtime(
                context_clone,
                command_rx,
                ingest_clone,
                connected_clone,
                Arc::clone(&diagnostics_clone),
                ready_tx,
            )
            .await
            {
                push_diag_with_storage(
                    &diagnostics_clone,
                    &ingest_for_error,
                    None,
                    now_ms(),
                    "runtime_error",
                    error,
                    "ws_bridge",
                );
            }
        });
    });

    match ready_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = join_handle.join();
            return Err(BridgeError::Io(error));
        }
        Err(_) => {
            let _ = join_handle.join();
            return Err(BridgeError::Timeout);
        }
    }

    Ok(CaptureBridgeHandle {
        token: context.token.clone(),
        context,
        command_tx,
        diagnostics,
        connected,
        ingest_service,
        request_counter: AtomicU64::new(0),
        join_handle: Some(join_handle),
    })
}

async fn run_ws_runtime(
    context: PairingContext,
    mut command_rx: UnboundedReceiver<RuntimeCommand>,
    ingest_service: Arc<Mutex<DesktopIngestService>>,
    connected: Arc<AtomicBool>,
    diagnostics: Arc<Mutex<Vec<BridgeDiagnostic>>>,
    ready_tx: mpsc::Sender<Result<(), String>>,
) -> Result<(), String> {
    let bind_addr = format!("127.0.0.1:{}", context.port);
    let listener = TcpListener::bind(&bind_addr).await;
    let listener = match listener {
        Ok(listener) => {
            let _ = ready_tx.send(Ok(()));
            listener
        }
        Err(error) => {
            let message = format!("bind failed: {error}");
            let _ = ready_tx.send(Err(message.clone()));
            return Err(message);
        }
    };

    let (runtime_event_tx, mut runtime_event_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut writer_tx: Option<UnboundedSender<JsonEnvelope>> = None;
    let mut active_connection_id: u64 = 0;
    let mut pending: HashMap<String, PendingRequest> = HashMap::new();

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _) = match accept {
                    Ok(pair) => pair,
                    Err(error) => {
                        push_diag_with_storage(
                            &diagnostics,
                            &ingest_service,
                            None,
                            now_ms(),
                            "accept_error",
                            error.to_string(),
                            "ws_bridge",
                        );
                        continue;
                    }
                };

                let token = context.token.clone();
                let runtime_event_tx_clone = runtime_event_tx.clone();
                let diagnostics_clone = Arc::clone(&diagnostics);
                let ingest_clone = Arc::clone(&ingest_service);
                active_connection_id += 1;
                let connection_id = active_connection_id;
                tokio::spawn(async move {
                    match accept_with_auth_or_discovery(stream, token.clone()).await {
                        Ok(AcceptedSocket::Discovery { mut ws, device_id, browser_label }) => {
                            let ts_ms = now_ms();
                            if let Ok(mut service) = ingest_clone.lock() {
                                let _ = service
                                    .storage()
                                    .upsert_trusted_device(&device_id, &browser_label, ts_ms);
                                let _ = service.append_bridge_diagnostic(
                                    None,
                                    ts_ms,
                                    "pairing_discovered",
                                    &format!("device_id={device_id} browser_label={browser_label}"),
                                    "ws_bridge",
                                );
                            }

                            let payload = serde_json::to_value(EvtPairingDiscoveredPayload {
                                state: PairingUxStateV1::Paired,
                                device_id: device_id.clone(),
                            })
                            .unwrap_or_else(|_| serde_json::json!({ "state": "paired", "device_id": device_id }));

                            let envelope = JsonEnvelope {
                                v: ENVELOPE_VERSION,
                                envelope_type: "evt.pairing_discovered".to_string(),
                                ts_ms,
                                token: Some(token),
                                request_id: None,
                                correlation_id: None,
                                session_id: None,
                                event_seq: None,
                                privacy_mode: None,
                                payload,
                            };

                            if let Ok(text) = to_json_text(&envelope) {
                                let _ = ws.send(Message::Text(text)).await;
                            }
                            let _ = ws.close(None).await;
                        }
                        Ok(AcceptedSocket::Authenticated(ws)) => {
                            let (mut sink, mut stream) = ws.split();
                            let (writer_tx_inner, mut writer_rx_inner) = tokio::sync::mpsc::unbounded_channel::<JsonEnvelope>();

                            let runtime_event_tx_writer = runtime_event_tx_clone.clone();
                            tokio::spawn(async move {
                                while let Some(envelope) = writer_rx_inner.recv().await {
                                    match to_json_text(&envelope) {
                                        Ok(text) => {
                                            if sink.send(Message::Text(text)).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                let _ = runtime_event_tx_writer.send(RuntimeEvent::Closed {
                                    connection_id,
                                });
                            });

                            let _ = runtime_event_tx_clone.send(RuntimeEvent::Connected {
                                connection_id,
                                writer_tx: writer_tx_inner,
                            });
                            while let Some(message) = stream.next().await {
                                match message {
                                    Ok(Message::Text(text)) => {
                                        match from_json_text(&text) {
                                            Ok(envelope) => {
                                                let _ = runtime_event_tx_clone.send(
                                                    RuntimeEvent::Incoming {
                                                        connection_id,
                                                        envelope: Box::new(envelope),
                                                    },
                                                );
                                            }
                                            Err(error) => {
                                                push_diag_with_storage(
                                                    &diagnostics_clone,
                                                    &ingest_clone,
                                                    None,
                                                    now_ms(),
                                                    "decode_error",
                                                    error.to_string(),
                                                    "ws_bridge",
                                                );
                                            }
                                        }
                                    }
                                    Ok(Message::Close(_)) => {
                                        break;
                                    }
                                    Ok(_) => {}
                                    Err(error) => {
                                        push_diag_with_storage(
                                            &diagnostics_clone,
                                            &ingest_clone,
                                            None,
                                            now_ms(),
                                            "socket_error",
                                            error.to_string(),
                                            "ws_bridge",
                                        );
                                        break;
                                    }
                                }
                            }
                            let _ = runtime_event_tx_clone.send(RuntimeEvent::Closed {
                                connection_id,
                            });
                        }
                        Err(error) => {
                            push_diag_with_storage(
                                &diagnostics_clone,
                                &ingest_clone,
                                None,
                                now_ms(),
                                "auth_reject",
                                error.to_string(),
                                "ws_bridge",
                            );
                        }
                    }
                });
            }
            Some(runtime_command) = command_rx.recv() => {
                match runtime_command {
                    RuntimeCommand::Stop => {
                        break;
                    }
                    RuntimeCommand::Send { envelope, expected_type, tx } => {
                        let Some(request_id) = envelope.request_id.clone() else {
                            let _ = tx.send(Err(BridgeError::InvalidResponse("missing request_id".to_string())));
                            continue;
                        };

                        if let Some(writer) = &writer_tx {
                            pending.insert(request_id.clone(), PendingRequest { expected_type, tx });
                            if writer.send(*envelope).is_err() {
                                if let Some(pending_request) = pending.remove(&request_id) {
                                    let _ = pending_request.tx.send(Err(BridgeError::WsDisconnected));
                                }
                            }
                        } else {
                            let _ = tx.send(Err(BridgeError::WsDisconnected));
                        }
                    }
                }
            }
            Some(runtime_event) = runtime_event_rx.recv() => {
                match runtime_event {
                    RuntimeEvent::Connected { connection_id, writer_tx: next_writer } => {
                        if writer_tx.is_some() {
                            push_diag_with_storage(
                                &diagnostics,
                                &ingest_service,
                                None,
                                now_ms(),
                                "connection_replaced",
                                "new extension connection replaced previous one",
                                "ws_bridge",
                            );
                        }
                        writer_tx = Some(next_writer);
                        active_connection_id = connection_id;
                        connected.store(true, Ordering::Relaxed);
                        push_diag_with_storage(
                            &diagnostics,
                            &ingest_service,
                            None,
                            now_ms(),
                            "connected",
                            "extension websocket connected",
                            "ws_bridge",
                        );
                        emit_metric(
                            &ingest_service,
                            None,
                            ReliabilityMetricKeyV1::WsReconnectCount,
                            now_ms(),
                            "ws_bridge",
                            json!({"state": "connected"}),
                        );
                    }
                    RuntimeEvent::Incoming { connection_id, envelope: event_envelope } => {
                        if connection_id != active_connection_id {
                            continue;
                        }
                        route_event(&event_envelope, &ingest_service, &diagnostics);
                        if let Some(correlation_id) = correlation_id_of(&event_envelope) {
                            if let Some(pending_request) = pending.get(correlation_id) {
                                if event_matches_pending(&event_envelope, &pending_request.expected_type) {
                                    let pending_request = pending.remove(correlation_id).expect("pending exists");
                                    let _ = pending_request.tx.send(Ok(*event_envelope));
                                }
                            }
                        }
                    }
                    RuntimeEvent::Closed { connection_id } => {
                        if connection_id != active_connection_id {
                            continue;
                        }
                        writer_tx = None;
                        connected.store(false, Ordering::Relaxed);
                        for (_, pending_request) in pending.drain() {
                            let _ = pending_request.tx.send(Err(BridgeError::WsDisconnected));
                        }
                        push_diag_with_storage(
                            &diagnostics,
                            &ingest_service,
                            None,
                            now_ms(),
                            "closed",
                            "extension websocket disconnected",
                            "ws_bridge",
                        );
                        emit_metric(
                            &ingest_service,
                            None,
                            ReliabilityMetricKeyV1::WsDisconnectCount,
                            now_ms(),
                            "ws_bridge",
                            json!({"state": "closed"}),
                        );
                    }
                }
            }
        }
    }

    connected.store(false, Ordering::Relaxed);
    Ok(())
}

#[allow(clippy::result_large_err)]
async fn accept_with_auth_or_discovery(
    stream: tokio::net::TcpStream,
    token: String,
) -> Result<AcceptedSocket, tungstenite::Error> {
    let mut mode: Option<AcceptMode> = None;
    let ws = accept_hdr_async(stream, |request: &Request, response: Response| {
        let path = request.uri().path();
        let query = request.uri().query().unwrap_or_default();

        if path == "/ws" {
            let received_token = query_value(query, "token");
            if received_token.as_deref() != Some(token.as_str()) {
                return Err(error_response(StatusCode::UNAUTHORIZED, "invalid token"));
            }
            mode = Some(AcceptMode::Authenticated);
            return Ok(response);
        }

        if path == "/pairing-discover" {
            let device_id = query_value(query, "device_id")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "unknown_device".to_string());
            let browser_label = query_value(query, "browser_label")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "Chrome Extension".to_string());
            mode = Some(AcceptMode::Discovery { device_id, browser_label });
            return Ok(response);
        }

        Err(error_response(StatusCode::NOT_FOUND, "invalid path"))
    })
    .await?;

    match mode {
        Some(AcceptMode::Authenticated) => Ok(AcceptedSocket::Authenticated(ws)),
        Some(AcceptMode::Discovery { device_id, browser_label }) => {
            Ok(AcceptedSocket::Discovery { ws, device_id, browser_label })
        }
        None => Err(tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::HandshakeIncomplete,
        )),
    }
}

fn error_response(status: StatusCode, body: &str) -> ErrorResponse {
    let mut response = ErrorResponse::new(Some(body.to_string()));
    *response.status_mut() = status;
    response
}

fn query_value(query: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes()).find_map(|(k, v)| {
        if k == key {
            Some(v.into_owned())
        } else {
            None
        }
    })
}

fn parse_error_message(envelope: &JsonEnvelope) -> String {
    parse_error_payload(envelope)
        .map(|payload: EvtErrorPayload| payload.message)
        .unwrap_or_else(|_| "extension error".to_string())
}

fn route_event(
    envelope: &JsonEnvelope,
    ingest_service: &Arc<Mutex<DesktopIngestService>>,
    diagnostics: &Arc<Mutex<Vec<BridgeDiagnostic>>>,
) {
    if envelope.envelope_type == EVT_RAW_EVENT {
        if let Ok(mut service) = ingest_service.lock() {
            if let Err(error) = service.ingest_event_envelope(envelope) {
                let message = error.to_string();
                let ts_ms = now_ms();
                push_diag(
                    diagnostics,
                    BridgeDiagnostic {
                        ts_ms,
                        kind: "ingest_error".to_string(),
                        message: message.clone(),
                    },
                );
                let _ = service.append_bridge_diagnostic(
                    envelope.session_id.as_deref(),
                    ts_ms,
                    "ingest_error",
                    &message,
                    "ws_bridge",
                );
            }
            let cdp_method = envelope
                .payload
                .get("cdp_method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if cdp_method == "DTT.capture_drop.v1" {
                let _ = service.append_reliability_metric(
                    envelope.session_id.as_deref(),
                    "extension",
                    ReliabilityMetricKeyV1::CaptureDropCount,
                    1.0,
                    &json!({"marker": "capture_drop"}),
                    envelope.ts_ms,
                );
            } else if cdp_method == "DTT.capture_limit.v1" {
                let _ = service.append_reliability_metric(
                    envelope.session_id.as_deref(),
                    "extension",
                    ReliabilityMetricKeyV1::CaptureLimitCount,
                    1.0,
                    &json!({"marker": "capture_limit"}),
                    envelope.ts_ms,
                );
            }
        }
        return;
    }

    if envelope.envelope_type == EVT_SESSION_STARTED {
        if let Ok(payload) = parse_session_started_payload(envelope) {
            if let Ok(mut service) = ingest_service.lock() {
                if let Err(error) = service.begin_session(
                    &payload.session_id,
                    payload.privacy_mode,
                    payload.started_at_ms,
                    "extension_mv3",
                ) {
                    let message = error.to_string();
                    let ts_ms = now_ms();
                    push_diag(
                        diagnostics,
                        BridgeDiagnostic {
                            ts_ms,
                            kind: "session_start_error".to_string(),
                            message: message.clone(),
                        },
                    );
                    let _ = service.append_bridge_diagnostic(
                        Some(&payload.session_id),
                        ts_ms,
                        "session_start_error",
                        &message,
                        "ws_bridge",
                    );
                }
            }
        }
        return;
    }

    if envelope.envelope_type == EVT_SESSION_ENDED {
        if let Ok(payload) = parse_session_ended_payload(envelope) {
            if let Ok(mut service) = ingest_service.lock() {
                if let Err(error) = service.end_session(&payload.session_id, payload.ended_at_ms) {
                    let message = error.to_string();
                    let ts_ms = now_ms();
                    push_diag(
                        diagnostics,
                        BridgeDiagnostic {
                            ts_ms,
                            kind: "session_end_error".to_string(),
                            message: message.clone(),
                        },
                    );
                    let _ = service.append_bridge_diagnostic(
                        Some(&payload.session_id),
                        ts_ms,
                        "session_end_error",
                        &message,
                        "ws_bridge",
                    );
                    return;
                }
                if let Err(error) = service.normalize_session(&payload.session_id) {
                    let message = error.to_string();
                    let ts_ms = now_ms();
                    push_diag(
                        diagnostics,
                        BridgeDiagnostic {
                            ts_ms,
                            kind: "normalize_error".to_string(),
                            message: message.clone(),
                        },
                    );
                    let _ = service.append_bridge_diagnostic(
                        Some(&payload.session_id),
                        ts_ms,
                        "normalize_error",
                        &message,
                        "pipeline",
                    );
                    let _ = service.append_reliability_metric(
                        Some(&payload.session_id),
                        "pipeline",
                        ReliabilityMetricKeyV1::SessionPipelineFailCount,
                        1.0,
                        &json!({"stage": "normalize"}),
                        ts_ms,
                    );
                    return;
                }
                if let Err(error) = service.correlate_session(&payload.session_id) {
                    let message = error.to_string();
                    let ts_ms = now_ms();
                    push_diag(
                        diagnostics,
                        BridgeDiagnostic {
                            ts_ms,
                            kind: "correlate_error".to_string(),
                            message: message.clone(),
                        },
                    );
                    let _ = service.append_bridge_diagnostic(
                        Some(&payload.session_id),
                        ts_ms,
                        "correlate_error",
                        &message,
                        "pipeline",
                    );
                    let _ = service.append_reliability_metric(
                        Some(&payload.session_id),
                        "pipeline",
                        ReliabilityMetricKeyV1::SessionPipelineFailCount,
                        1.0,
                        &json!({"stage": "correlate"}),
                        ts_ms,
                    );
                    return;
                }
                if let Err(error) = service.analyze_session(&payload.session_id) {
                    let message = error.to_string();
                    let ts_ms = now_ms();
                    push_diag(
                        diagnostics,
                        BridgeDiagnostic {
                            ts_ms,
                            kind: "analyze_error".to_string(),
                            message: message.clone(),
                        },
                    );
                    let _ = service.append_bridge_diagnostic(
                        Some(&payload.session_id),
                        ts_ms,
                        "analyze_error",
                        &message,
                        "pipeline",
                    );
                    let _ = service.append_reliability_metric(
                        Some(&payload.session_id),
                        "pipeline",
                        ReliabilityMetricKeyV1::SessionPipelineFailCount,
                        1.0,
                        &json!({"stage": "analyze"}),
                        ts_ms,
                    );
                } else {
                    let ts_ms = now_ms();
                    push_diag(
                        diagnostics,
                        BridgeDiagnostic {
                            ts_ms,
                            kind: "session_close_pipeline_ok".to_string(),
                            message: "normalize/correlate/analyze completed".to_string(),
                        },
                    );
                    let _ = service.append_bridge_diagnostic(
                        Some(&payload.session_id),
                        ts_ms,
                        "session_close_pipeline_ok",
                        "normalize/correlate/analyze completed",
                        "pipeline",
                    );
                }
            }
        }
        return;
    }

    if envelope.envelope_type == EVT_HELLO {
        if let Ok(payload) = parse_hello_payload(envelope) {
            push_diag_with_storage(
                diagnostics,
                ingest_service,
                envelope.session_id.as_deref(),
                envelope.ts_ms,
                "hello",
                format!(
                    "connected={} consent={} ui_capture={}",
                    payload.connected, payload.consent_enabled, payload.ui_capture_enabled
                ),
                "ws_bridge",
            );
        }
        return;
    }

    if envelope.envelope_type == EVT_ERROR {
        let parsed = parse_error_payload(envelope);
        let message = parsed
            .as_ref()
            .map(|payload| format!("{:?}: {}", payload.code, payload.message))
            .unwrap_or_else(|_| "evt.error (unparseable payload)".to_string());
        push_diag_with_storage(
            diagnostics,
            ingest_service,
            envelope.session_id.as_deref(),
            envelope.ts_ms,
            "error",
            message,
            "ws_bridge",
        );
        if let Ok(payload) = parsed {
            let key = match payload.code {
                dtt_core::EventErrorCodeV1::PermissionDenied => {
                    Some(ReliabilityMetricKeyV1::PermissionDeniedCount)
                }
                dtt_core::EventErrorCodeV1::AlreadyAttached => {
                    Some(ReliabilityMetricKeyV1::AlreadyAttachedCount)
                }
                _ => None,
            };
            if let Some(metric_key) = key {
                emit_metric(
                    ingest_service,
                    envelope.session_id.as_deref(),
                    metric_key,
                    envelope.ts_ms,
                    "extension",
                    json!({"code": payload.code}),
                );
            }
        }
    }
}

fn push_diag(diagnostics: &Arc<Mutex<Vec<BridgeDiagnostic>>>, next: BridgeDiagnostic) {
    if let Ok(mut guard) = diagnostics.lock() {
        guard.push(next);
        if guard.len() > 500 {
            let overflow = guard.len() - 500;
            guard.drain(0..overflow);
        }
    }
}

fn push_diag_with_storage(
    diagnostics: &Arc<Mutex<Vec<BridgeDiagnostic>>>,
    ingest_service: &Arc<Mutex<DesktopIngestService>>,
    session_id: Option<&str>,
    ts_ms: i64,
    kind: &str,
    message: impl Into<String>,
    source: &str,
) {
    let message = message.into();
    push_diag(
        diagnostics,
        BridgeDiagnostic { ts_ms, kind: kind.to_string(), message: message.clone() },
    );
    if let Ok(mut service) = ingest_service.lock() {
        let _ = service.append_bridge_diagnostic(session_id, ts_ms, kind, &message, source);
    }
}

fn emit_metric(
    ingest_service: &Arc<Mutex<DesktopIngestService>>,
    session_id: Option<&str>,
    metric_key: ReliabilityMetricKeyV1,
    ts_ms: i64,
    source: &str,
    labels_json: serde_json::Value,
) {
    if let Ok(mut service) = ingest_service.lock() {
        let _ = service.append_reliability_metric(
            session_id,
            source,
            metric_key,
            1.0,
            &labels_json,
            ts_ms,
        );
    }
}

fn now_ms() -> i64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
