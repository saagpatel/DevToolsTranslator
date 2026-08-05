"use strict";

const HOST = "com.glassbox.browser";
const EXTENSION_ID = "giffhfldblangaphoeeeelcapcmedjbd";
const startButton = document.querySelector("#start");
const markerButton = document.querySelector("#marker");
const stopButton = document.querySelector("#stop");
const statusElement = document.querySelector("#status");

let port = null;
let context = null;
let challenge = null;
let credential = null;
let sequence = 0;
let requestOrdinal = 0;
let listening = false;

function token(prefix) {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `${prefix}_${Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("")}`;
}

function nowPayload(kind, fields = {}) {
  return {
    kind,
    observed_unix_ns: String(BigInt(Date.now()) * 1000000n),
    uncertainty_ns: 50000000,
    ...fields,
  };
}

function setStatus(message) { statusElement.textContent = message; }

function sendFrame(payload) {
  if (!port || !credential || !context) return;
  sequence += 1;
  port.postMessage({
    type: "frame",
    frame: {
      protocol_version: 1,
      context,
      session_token: credential.token,
      sequence,
      payload,
    },
  });
}

function resourceType(request) {
  const candidate = String(request._resourceType || "other").toLowerCase();
  return ["document", "stylesheet", "image", "media", "font", "script", "xhr", "fetch", "websocket"].includes(candidate)
    ? candidate : "other";
}

function installListeners() {
  if (listening) return;
  listening = true;
  chrome.devtools.network.onNavigated.addListener(url => {
    sendFrame(nowPayload("navigation", { url }));
    sendFrame(nowPayload("gap", { reason: "tab_navigated", dropped_count: 0 }));
  });
  chrome.devtools.network.onRequestFinished.addListener(request => {
    const requestId = `request_${++requestOrdinal}`;
    sendFrame(nowPayload("request", {
      request_id: requestId,
      method: String(request.request.method || "GET").toUpperCase(),
      resource_type: resourceType(request),
      url: request.request.url,
    }));
    sendFrame(nowPayload("response", {
      request_id: requestId,
      status: Number(request.response.status),
      encoded_body_bytes: Math.max(0, Number(request.response.bodySize || 0)),
    }));
  });
}

function handleMessage(message) {
  if (message.type === "challenge") {
    challenge = message.challenge;
    port.postMessage({ type: "exchange", challenge });
  } else if (message.type === "credential") {
    credential = message.credential;
    installListeners();
    sendFrame(nowPayload("gap", { reason: "devtools_opened_late", dropped_count: 0 }));
    startButton.disabled = true;
    markerButton.disabled = false;
    stopButton.disabled = false;
    setStatus("Capturing metadata from this inspected tab. Headers and bodies are excluded.");
  } else if (message.type === "completed") {
    setStatus(`Evidence sealed as ${message.file_name}. Open Glassbox Browser Adapter to export it.`);
    startButton.disabled = false;
    markerButton.disabled = true;
    stopButton.disabled = true;
    credential = null;
    port.disconnect();
    port = null;
  } else if (message.type === "rejected") {
    setStatus("The native host rejected the session. No evidence was published.");
  }
}

startButton.addEventListener("click", () => {
  context = {
    extension_id: EXTENSION_ID,
    browser_attachment_id: token("attachment"),
    selected_tab_id: chrome.devtools.inspectedWindow.tabId,
    request_id: token("request"),
    session_nonce: token("nonce"),
  };
  sequence = 0;
  requestOrdinal = 0;
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener(handleMessage);
  port.onDisconnect.addListener(() => {
    if (credential) setStatus("Capture disconnected before explicit stop. No completed evidence was published.");
    credential = null;
    markerButton.disabled = true;
    stopButton.disabled = true;
    startButton.disabled = false;
  });
  port.postMessage({
    type: "attach",
    request: {
      protocol_version: 1,
      context,
      foreground_user_gesture: true,
      visible_approval: true,
      selected_tab_count: 1,
    },
  });
  setStatus("Requesting a one-use native attachment challenge…");
});

markerButton.addEventListener("click", () => {
  sendFrame(nowPayload("user_action", { action: "click" }));
  setStatus("Manual marker recorded as user-asserted evidence.");
});

stopButton.addEventListener("click", () => {
  stopButton.disabled = true;
  markerButton.disabled = true;
  sendFrame(nowPayload("stop"));
  setStatus("Stopping and validating the evidence bundle…");
});
