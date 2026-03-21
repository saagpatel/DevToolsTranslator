import { CaptureBuffer } from './buffer.js';
import {
  makeErrorEvent,
  makeHelloEvent,
  makeRawEventEnvelope,
  makeSessionEndedEvent,
  makeSessionStartedEvent,
  makeTabsListEvent,
  mapAttachError,
  nowMs,
  parseEnvelope,
  serializeEnvelope,
  type ControlEnvelopeV1,
  type ErrorPayload,
  type EventErrorCode,
  type PairingUxState,
  type RawEventPayload,
  type RedactionLevel,
  type SessionEndedPayload,
  type SessionStartedPayload,
  type SetUiCaptureCommandPayload,
  type StartCaptureCommandPayload,
  type StopCaptureCommandPayload,
  type TabDescriptor,
} from './protocol.js';
import { sanitizeRawEvent } from './privacy.js';
import { reconnectDelayMs } from './reconnect.js';

interface PairingSettings {
  port: number | null;
  token: string | null;
  trusted_device_id: string | null;
  trusted: boolean;
  pairing_state: PairingUxState;
}

interface CaptureState {
  session_id: string;
  tab_id: number;
  privacy_mode: RedactionLevel;
  event_seq: number;
  attached: boolean;
}

interface ExtensionState {
  pairing: PairingSettings;
  connection_status: 'disconnected' | 'connecting' | 'connected';
  consent_enabled: boolean;
  ui_capture_enabled: boolean;
  capture: CaptureState | null;
}

const STORAGE_KEYS = {
  pairingPort: 'pairing.port',
  pairingToken: 'pairing.token',
  pairingTrustedDeviceId: 'pairing.trusted_device_id',
  pairingTrusted: 'pairing.trusted',
  pairingState: 'pairing.state',
  connectionStatus: 'connection.status',
  consentEnabled: 'consent.enabled',
  uiCaptureEnabled: 'ui_capture.enabled',
} as const;

const state: ExtensionState = {
  pairing: {
    port: null,
    token: null,
    trusted_device_id: null,
    trusted: false,
    pairing_state: 'not_paired',
  },
  connection_status: 'disconnected',
  consent_enabled: false,
  ui_capture_enabled: false,
  capture: null,
};

const buffer = new CaptureBuffer();
let socket: WebSocket | null = null;
let stoppingCapture = false;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempt = 0;
let reconnectEnabled = true;
let disconnectMarkerSent = false;

void bootstrap();

chrome.debugger.onEvent.addListener((source, method, params) => {
  const capture = state.capture;
  if (!capture || !capture.attached || source.tabId !== capture.tab_id) {
    return;
  }

  const rawEvent = {
    method,
    params: (params ?? {}) as Record<string, unknown>,
  } as Record<string, unknown>;
  const sanitized = sanitizeRawEvent(rawEvent, capture.privacy_mode);

  const nextSeq = nextEventSeq();
  const payload: RawEventPayload = {
    event_id: `evt_${capture.session_id}_${nextSeq}`,
    cdp_method: method,
    raw_event: sanitized.raw_event,
  };

  queueRawEnvelope(
    makeRawEventEnvelope({
      session_id: capture.session_id,
      event_seq: nextSeq,
      privacy_mode: capture.privacy_mode,
      payload,
    }),
  );

  if (sanitized.body_limit_hit) {
    const markerSeq = nextEventSeq();
    const markerPayload: RawEventPayload = {
      event_id: `evt_${capture.session_id}_${markerSeq}`,
      cdp_method: 'DTT.capture_limit.v1',
      raw_event: {
        method: 'DTT.capture_limit.v1',
        params: {
          max_body_bytes: 2_000_000,
          observed_body_bytes: sanitized.body_limit_len,
          privacy_mode: capture.privacy_mode,
        },
      },
    };
    queueRawEnvelope(
      makeRawEventEnvelope({
        session_id: capture.session_id,
        event_seq: markerSeq,
        privacy_mode: capture.privacy_mode,
        payload: markerPayload,
      }),
    );
  }
});

chrome.debugger.onDetach.addListener((source, reason) => {
  const capture = state.capture;
  if (!capture || source.tabId !== capture.tab_id) {
    return;
  }

  const ended_at_ms = nowMs();
  state.capture = null;
  void persistState();

  if (stoppingCapture) {
    stoppingCapture = false;
    return;
  }

  sendControlEnvelope(
    makeErrorEvent({
      code: 'internal_error',
      message: `Debugger detached unexpectedly: ${reason}`,
      session_id: capture.session_id,
    }),
  );

  sendControlEnvelope(
    makeSessionEndedEvent({
      session_id: capture.session_id,
      ended_at_ms,
    }),
  );
});

chrome.runtime.onMessage.addListener((message: Record<string, unknown>, _sender, sendResponse) => {
  void (async () => {
    const action = String(message.action ?? '');
    switch (action) {
      case 'state.get': {
        sendResponse({ ok: true, state: toUiState() });
        return;
      }
      case 'pairing.set': {
        const port = Number(message.port);
        const token = String(message.token ?? '').trim();
        if (!Number.isInteger(port) || port < 32123 || port > 32133 || token.length < 8) {
          sendResponse({ ok: false, error: 'Invalid pairing input' });
          return;
        }
        state.pairing.port = port;
        state.pairing.token = token;
        state.pairing.pairing_state = 'paired';
        state.pairing.trusted = true;
        state.pairing.trusted_device_id = chrome.runtime.id;
        await persistState();
        sendResponse({ ok: true, state: toUiState() });
        return;
      }
      case 'pairing.discover': {
        const discovered = await discoverDesktopApp();
        if (!discovered) {
          sendResponse({
            ok: false,
            error: 'Unable to find a running Desktop App. Open the app and try again.',
            state: toUiState(),
          });
          return;
        }
        sendResponse({ ok: true, state: toUiState() });
        return;
      }
      case 'ws.connect': {
        await connectSocket();
        sendResponse({ ok: true, state: toUiState() });
        return;
      }
      case 'ws.disconnect': {
        disconnectSocket('manual');
        await persistState();
        sendResponse({ ok: true, state: toUiState() });
        return;
      }
      case 'consent.set': {
        state.consent_enabled = Boolean(message.enabled);
        await persistState();
        emitHelloUpdate();
        sendResponse({ ok: true, state: toUiState() });
        return;
      }
      case 'ui_capture.set': {
        const enabled = Boolean(message.enabled);
        if (enabled) {
          try {
            await requestOptionalOrigins();
          } catch {
            // Best effort only.
          }
        }
        state.ui_capture_enabled = enabled;
        await persistState();
        emitHelloUpdate();
        sendResponse({ ok: true, state: toUiState() });
        return;
      }
      case 'desktop.open': {
        let launched = false;
        try {
          await chrome.tabs.create({ url: 'dtt://open' });
          launched = true;
        } catch {
          launched = false;
        }
        sendResponse({
          ok: launched,
          state: toUiState(),
          error: launched ? undefined : 'Desktop deep-link did not open. Start the Desktop App manually.',
        });
        return;
      }
      case 'sidepanel.open': {
        try {
          const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
          const windowId = active?.windowId;
          if (windowId !== undefined && chrome.sidePanel?.open) {
            await chrome.sidePanel.open({ windowId });
          }
          sendResponse({ ok: true, state: toUiState() });
        } catch {
          sendResponse({ ok: false, error: 'Unable to open side panel', state: toUiState() });
        }
        return;
      }
      default: {
        sendResponse({ ok: false, error: 'Unsupported action' });
      }
    }
  })();
  return true;
});

async function bootstrap(): Promise<void> {
  const stored = await chrome.storage.local.get([
    STORAGE_KEYS.pairingPort,
    STORAGE_KEYS.pairingToken,
    STORAGE_KEYS.pairingTrustedDeviceId,
    STORAGE_KEYS.pairingTrusted,
    STORAGE_KEYS.pairingState,
    STORAGE_KEYS.connectionStatus,
    STORAGE_KEYS.consentEnabled,
    STORAGE_KEYS.uiCaptureEnabled,
  ]);

  state.pairing.port = typeof stored[STORAGE_KEYS.pairingPort] === 'number'
    ? (stored[STORAGE_KEYS.pairingPort] as number)
    : null;
  state.pairing.token = typeof stored[STORAGE_KEYS.pairingToken] === 'string'
    ? (stored[STORAGE_KEYS.pairingToken] as string)
    : null;
  state.pairing.trusted_device_id = typeof stored[STORAGE_KEYS.pairingTrustedDeviceId] === 'string'
    ? (stored[STORAGE_KEYS.pairingTrustedDeviceId] as string)
    : null;
  state.pairing.trusted = Boolean(stored[STORAGE_KEYS.pairingTrusted]);
  state.pairing.pairing_state =
    (stored[STORAGE_KEYS.pairingState] as PairingUxState | undefined) ?? 'not_paired';
  state.connection_status =
    stored[STORAGE_KEYS.connectionStatus] === 'connected' ? 'connected' : 'disconnected';
  state.consent_enabled = Boolean(stored[STORAGE_KEYS.consentEnabled]);
  state.ui_capture_enabled = Boolean(stored[STORAGE_KEYS.uiCaptureEnabled]);

  if (state.pairing.trusted) {
    if (!state.pairing.token || !state.pairing.port) {
      await discoverDesktopApp();
    }
    await connectSocket();
  }
}

async function connectSocket(): Promise<void> {
  if (socket && socket.readyState === WebSocket.OPEN) {
    return;
  }

  if (!state.pairing.token || !state.pairing.port) {
    const discovered = await discoverDesktopApp();
    if (!discovered) {
      state.pairing.pairing_state = 'error';
      await persistState();
      return;
    }
  }

  if (!(await ensureLocalhostPermission())) {
    state.pairing.pairing_state = 'error';
    await persistState();
    return;
  }

  const token = state.pairing.token;
  const port = state.pairing.port;
  if (!token || !port) {
    state.pairing.pairing_state = 'error';
    state.connection_status = 'disconnected';
    await persistState();
    return;
  }

  disconnectSocket('reset');
  reconnectEnabled = true;
  state.pairing.pairing_state = 'reconnecting';
  state.connection_status = 'connecting';
  await persistState();

  const wsUrl = `ws://127.0.0.1:${port}/ws?token=${encodeURIComponent(token)}`;
  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    reconnectAttempt = 0;
    disconnectMarkerSent = false;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    state.connection_status = 'connected';
    state.pairing.trusted = true;
    state.pairing.trusted_device_id = chrome.runtime.id;
    state.pairing.pairing_state = 'paired';
    void persistState();
    sendControlEnvelope(makeHelloEvent(buildHelloPayload()));
    flushRawBuffer();
  };

  socket.onmessage = (event) => {
    void handleIncomingMessage(String(event.data ?? ''));
  };

  socket.onclose = () => {
    handleSocketDisconnected('close');
  };

  socket.onerror = () => {
    handleSocketDisconnected('error');
  };
}

function disconnectSocket(mode: 'manual' | 'reset' = 'manual'): void {
  if (mode === 'manual') {
    reconnectEnabled = false;
    state.pairing.pairing_state = state.pairing.trusted ? 'paired' : 'not_paired';
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (socket) {
    try {
      socket.close();
    } catch {
      // no-op
    }
  }
  socket = null;
  state.connection_status = 'disconnected';
}

function handleSocketDisconnected(reason: 'close' | 'error'): void {
  socket = null;
  state.connection_status = 'disconnected';
  state.pairing.pairing_state = state.pairing.trusted ? 'reconnecting' : 'error';
  void persistState();

  if (state.capture && !disconnectMarkerSent) {
    disconnectMarkerSent = true;
    const markerSeq = nextEventSeq();
    queueRawEnvelope(
      makeRawEventEnvelope({
        session_id: state.capture.session_id,
        event_seq: markerSeq,
        privacy_mode: state.capture.privacy_mode,
        payload: {
          event_id: `evt_${state.capture.session_id}_${markerSeq}`,
          cdp_method: 'DTT.desktop_disconnect.v1',
          raw_event: {
            method: 'DTT.desktop_disconnect.v1',
            params: {
              reason,
              reconnect_attempt: reconnectAttempt,
            },
          },
        },
      }),
    );
  }

  if (!reconnectEnabled || !state.pairing.port || !state.pairing.token) {
    return;
  }
  if (reconnectTimer) {
    return;
  }

  const delay = reconnectDelayMs(reconnectAttempt);
  reconnectAttempt += 1;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    void connectSocket();
  }, delay);
}


async function handleIncomingMessage(raw: string): Promise<void> {
  let envelope: ControlEnvelopeV1;
  try {
    envelope = parseEnvelope(raw);
  } catch {
    sendControlEnvelope(
      makeErrorEvent({
        code: 'internal_error',
        message: 'Failed to parse command envelope',
      }),
    );
    return;
  }

  switch (envelope.type) {
    case 'cmd.list_tabs':
      await handleListTabs(envelope.request_id);
      break;
    case 'cmd.start_capture':
      await handleStartCapture(envelope);
      break;
    case 'cmd.stop_capture':
      await handleStopCapture(envelope);
      break;
    case 'cmd.set_ui_capture':
      await handleSetUiCapture(envelope);
      break;
    default:
      sendControlEnvelope(
        makeErrorEvent(
          {
            code: 'unsupported_command',
            message: `Unsupported command: ${envelope.type}`,
          },
          envelope.request_id,
        ),
      );
  }
}

async function handleListTabs(correlation_id?: string): Promise<void> {
  const tabs = await queryEligibleTabs();
  sendControlEnvelope(makeTabsListEvent({ tabs }, correlation_id));
}

async function handleStartCapture(envelope: ControlEnvelopeV1): Promise<void> {
  if (!state.consent_enabled) {
    sendControlEnvelope(
      makeErrorEvent(
        {
          code: 'permission_denied',
          message: 'Capture requires explicit consent in extension popup',
          session_id: envelope.session_id,
        },
        envelope.request_id,
      ),
    );
    return;
  }

  const payload = envelope.payload as unknown as StartCaptureCommandPayload;
  const session_id = payload.session_id ?? envelope.session_id;
  const tab_id = Number(payload.tab_id);
  const privacy_mode = (payload.privacy_mode ?? envelope.privacy_mode ?? 'metadata_only') as RedactionLevel;

  if (!session_id || !Number.isInteger(tab_id)) {
    sendControlEnvelope(
      makeErrorEvent(
        {
          code: 'unsupported_command',
          message: 'cmd.start_capture missing tab_id/session_id',
          session_id,
        },
        envelope.request_id,
      ),
    );
    return;
  }

  if (state.capture?.attached && state.capture.tab_id === tab_id && state.capture.session_id === session_id) {
    sendControlEnvelope(
      makeSessionStartedEvent(
        {
          session_id,
          tab_id,
          privacy_mode,
          started_at_ms: nowMs(),
        },
        envelope.request_id,
      ),
    );
    return;
  }

  if (state.capture?.attached && state.capture.tab_id !== tab_id) {
    sendControlEnvelope(
      makeErrorEvent(
        {
          code: 'already_attached',
          message: 'Extension is already attached to another tab',
          session_id,
        },
        envelope.request_id,
      ),
    );
    return;
  }

  const target = { tabId: tab_id } as chrome.debugger.Debuggee;

  try {
    await debuggerAttach(target, '1.3');
  } catch (error) {
    const message = String(error);
    const code = mapAttachError(message);
    sendControlEnvelope(
      makeErrorEvent(
        {
          code,
          message: `Unable to attach debugger: ${message}`,
          session_id,
        },
        envelope.request_id,
      ),
    );
    return;
  }

  try {
    await debuggerSendCommand(target, 'Network.enable', {});
    await debuggerSendCommand(target, 'Runtime.enable', {});
    await debuggerSendCommand(target, 'Log.enable', {});
    await debuggerSendCommand(target, 'Page.enable', {});
    if (payload.enable_security_domain) {
      await debuggerSendCommand(target, 'Security.enable', {});
    }
  } catch (error) {
    await safeDetach(target);
    sendControlEnvelope(
      makeErrorEvent(
        {
          code: 'internal_error',
          message: `Failed to enable CDP domains: ${String(error)}`,
          session_id,
        },
        envelope.request_id,
      ),
    );
    return;
  }

  state.capture = {
    session_id,
    tab_id,
    privacy_mode,
    event_seq: 0,
    attached: true,
  };
  disconnectMarkerSent = false;
  await persistState();

  const startedPayload: SessionStartedPayload = {
    session_id,
    tab_id,
    privacy_mode,
    started_at_ms: nowMs(),
  };
  sendControlEnvelope(makeSessionStartedEvent(startedPayload, envelope.request_id));
}

async function handleStopCapture(envelope: ControlEnvelopeV1): Promise<void> {
  const payload = envelope.payload as unknown as StopCaptureCommandPayload;
  const requestedSession = payload.session_id ?? envelope.session_id;
  const capture = state.capture;

  if (!capture) {
    if (requestedSession) {
      sendControlEnvelope(
        makeSessionEndedEvent(
          {
            session_id: requestedSession,
            ended_at_ms: nowMs(),
          },
          envelope.request_id,
        ),
      );
    }
    return;
  }

  const endedPayload: SessionEndedPayload = {
    session_id: capture.session_id,
    ended_at_ms: nowMs(),
  };

  stoppingCapture = true;
  await safeDetach({ tabId: capture.tab_id });
  stoppingCapture = false;

  state.capture = null;
  await persistState();

  flushRawBuffer();
  sendControlEnvelope(makeSessionEndedEvent(endedPayload, envelope.request_id));
}

async function handleSetUiCapture(envelope: ControlEnvelopeV1): Promise<void> {
  const payload = envelope.payload as unknown as SetUiCaptureCommandPayload;
  const enabled = Boolean(payload.enabled);
  if (enabled) {
    try {
      await requestOptionalOrigins();
    } catch {
      // Best effort in background command path.
    }
  }
  state.ui_capture_enabled = enabled;
  await persistState();
  sendControlEnvelope(makeHelloEvent(buildHelloPayload(), envelope.request_id));
}

async function queryEligibleTabs(): Promise<TabDescriptor[]> {
  const tabs = await chrome.tabs.query({});
  return tabs
    .filter((tab) => {
      const url = tab.url ?? '';
      return url.startsWith('http://') || url.startsWith('https://');
    })
    .map((tab) => ({
      tab_id: tab.id ?? -1,
      window_id: tab.windowId,
      url: tab.url ?? '',
      title: tab.title ?? '',
      active: Boolean(tab.active),
    }))
    .filter((tab) => tab.tab_id >= 0)
    .sort((left, right) => left.tab_id - right.tab_id);
}

function queueRawEnvelope(envelope: ControlEnvelopeV1<RawEventPayload>): void {
  const report = buffer.push(envelope);
  if (report.dropped_events > 0 && state.capture) {
    const markerSeq = nextEventSeq();
    const markerPayload: RawEventPayload = {
      event_id: `evt_${state.capture.session_id}_${markerSeq}`,
      cdp_method: 'DTT.capture_drop.v1',
      raw_event: {
        method: 'DTT.capture_drop.v1',
        params: {
          dropped_events: report.dropped_events,
          dropped_bytes: report.dropped_bytes,
          reason: 'buffer_cap',
        },
      },
    };
    const markerEnvelope = makeRawEventEnvelope({
      session_id: state.capture.session_id,
      event_seq: markerSeq,
      privacy_mode: state.capture.privacy_mode,
      payload: markerPayload,
    });
    void buffer.push(markerEnvelope);
  }

  flushRawBuffer();
}

function flushRawBuffer(): void {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }

  const pending = buffer.drain();
  for (let index = 0; index < pending.length; index += 1) {
    const next = pending[index];
    try {
      socket.send(serializeEnvelope(next));
    } catch {
      for (let remainder = index; remainder < pending.length; remainder += 1) {
        void buffer.push(pending[remainder]);
      }
      state.connection_status = 'disconnected';
      void persistState();
      break;
    }
  }
}

function sendControlEnvelope<TPayload>(envelope: ControlEnvelopeV1<TPayload>): void {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    return;
  }

  try {
    socket.send(serializeEnvelope(envelope));
  } catch {
    state.connection_status = 'disconnected';
    void persistState();
  }
}

function emitHelloUpdate(): void {
  sendControlEnvelope(makeHelloEvent(buildHelloPayload()));
}

function buildHelloPayload() {
  return {
    extension_version: chrome.runtime.getManifest().version,
    protocol_version: 1 as const,
    connected: state.connection_status === 'connected',
    consent_enabled: state.consent_enabled,
    ui_capture_enabled: state.ui_capture_enabled,
    active_session_id: state.capture?.session_id ?? null,
    pairing_state: state.pairing.pairing_state,
    trusted_device_id: state.pairing.trusted_device_id,
  };
}

function toUiState() {
  return {
    pairing: state.pairing,
    pairing_state: state.pairing.pairing_state,
    trusted_device_id: state.pairing.trusted_device_id,
    trusted: state.pairing.trusted,
    connection_status: state.connection_status,
    consent_enabled: state.consent_enabled,
    ui_capture_enabled: state.ui_capture_enabled,
    active_session_id: state.capture?.session_id ?? null,
    buffered_events: buffer.size(),
  };
}

function nextEventSeq(): number {
  if (!state.capture) {
    return 1;
  }
  state.capture.event_seq += 1;
  return state.capture.event_seq;
}

async function persistState(): Promise<void> {
  await chrome.storage.local.set({
    [STORAGE_KEYS.pairingPort]: state.pairing.port,
    [STORAGE_KEYS.pairingToken]: state.pairing.token,
    [STORAGE_KEYS.pairingTrustedDeviceId]: state.pairing.trusted_device_id,
    [STORAGE_KEYS.pairingTrusted]: state.pairing.trusted,
    [STORAGE_KEYS.pairingState]: state.pairing.pairing_state,
    [STORAGE_KEYS.connectionStatus]: state.connection_status,
    [STORAGE_KEYS.consentEnabled]: state.consent_enabled,
    [STORAGE_KEYS.uiCaptureEnabled]: state.ui_capture_enabled,
  });
}

async function ensureLocalhostPermission(): Promise<boolean> {
  const origins = ['http://127.0.0.1/*', 'http://localhost/*'];
  try {
    const contains = await chrome.permissions.contains({ origins });
    if (contains) {
      return true;
    }
    return chrome.permissions.request({ origins });
  } catch {
    // Required host_permissions should already cover localhost.
    return true;
  }
}

async function requestOptionalOrigins(): Promise<void> {
  await chrome.permissions.request({ origins: ['<all_urls>'] });
}

async function discoverDesktopApp(): Promise<boolean> {
  state.pairing.pairing_state = 'discovering';
  await persistState();

  if (!(await ensureLocalhostPermission())) {
    state.pairing.pairing_state = 'error';
    await persistState();
    return false;
  }

  for (let port = 32123; port <= 32133; port += 1) {
    if (state.connection_status === 'connected' && state.pairing.port === port && state.pairing.token) {
      return true;
    }
    const discovered = await probeDesktopDiscoveryPort(port);
    if (discovered) {
      state.pairing.port = port;
      state.pairing.token = discovered.token;
      state.pairing.trusted = true;
      state.pairing.trusted_device_id = discovered.device_id ?? chrome.runtime.id;
      state.pairing.pairing_state = 'paired';
      await persistState();
      return true;
    }
  }

  state.pairing.pairing_state = 'error';
  await persistState();
  return false;
}

function probeDesktopDiscoveryPort(
  port: number,
): Promise<{ token: string; device_id: string | null } | null> {
  return new Promise((resolve) => {
    const discoverUrl =
      `ws://127.0.0.1:${port}/pairing-discover?device_id=${encodeURIComponent(chrome.runtime.id)}&browser_label=${encodeURIComponent('Chrome Extension')}`;
    const ws = new WebSocket(discoverUrl);
    let settled = false;
    const finish = (result: { token: string; device_id: string | null } | null): void => {
      if (settled) {
        return;
      }
      settled = true;
      try {
        ws.close();
      } catch {
        // best effort
      }
      resolve(result);
    };

    const timeout = setTimeout(() => finish(null), 1400);
    ws.onerror = () => {
      clearTimeout(timeout);
      finish(null);
    };
    ws.onmessage = (event) => {
      clearTimeout(timeout);
      try {
        const parsed = JSON.parse(String(event.data ?? '')) as {
          readonly type?: string;
          readonly token?: string;
          readonly payload?: { readonly device_id?: string };
        };
        if (parsed.type !== 'evt.pairing_discovered' || typeof parsed.token !== 'string') {
          finish(null);
          return;
        }
        finish({
          token: parsed.token,
          device_id: parsed.payload?.device_id ?? null,
        });
      } catch {
        finish(null);
      }
    };
    ws.onclose = () => {
      if (!settled) {
        clearTimeout(timeout);
        finish(null);
      }
    };
  });
}

function debuggerAttach(target: chrome.debugger.Debuggee, version: string): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.debugger.attach(target, version, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve();
    });
  });
}

function debuggerSendCommand(
  target: chrome.debugger.Debuggee,
  method: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    chrome.debugger.sendCommand(target, method, params, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(result);
    });
  });
}

async function safeDetach(target: chrome.debugger.Debuggee): Promise<void> {
  await new Promise<void>((resolve) => {
    chrome.debugger.detach(target, () => {
      resolve();
    });
  });
}
