# Glassbox Donor Allowlist

Status: accepted for Gate 0 review
Owner: kernel owner and source-adapter owner

Code does not cross into Glassbox merely because it exists. Each imported behavior needs provenance, a focused test, a permission classification, and a review showing that prohibited adjacent behavior did not cross with it.

| Donor | Allowed contribution | Explicitly excluded | Long-term disposition |
|---|---|---|---|
| DevTools Translator | Repository scaffold, evidence-resolution concepts, deterministic/canonicalization ideas, browser adapter fixtures | Tauri/React shipping shell; WKWebView; legacy extension/host implementation; existing normalized schema as canonical kernel; current loopback discovery; global request IDs; fail-open sanitizer; fixed ZIP importer | Scaffold remains; native SwiftUI/AppKit shell replaces the donor UI/runtime; the separately distributed browser adapter is a clean implementation recorded in `provenance/browser-adapter.json` |
| Codec | Pure device/service models, conversation vocabulary, safe projections, metadata fixtures | Helper, LaunchDaemon, BPF permissions, capture, ARP spoofing, IP forwarding, raw/root paths | Candidate retirement after parity and soak |
| Grotto | Trace model concepts, critical-path/diff algorithms, OTLP fixtures/export adapter | Unauthenticated/unbounded receiver posture as core contract | Retain expert trace CLI/importer |
| Pulse Orbit | Bounded read-only aggregate system resource sampler logic and fixtures; adaptation receipt: `provenance/pulse-orbit-resource-sampler.json` | Alerts, history service, process identity, process killing, dashboard, network/disk/GPU collection, unbounded polling | Candidate retirement after aggregate sampler parity; the separate process-context adapter is a clean platform-API implementation and imports no Pulse process code |
| NetworkDecoder | Packet native locators, field-explanation concepts, constrained PCAP fixtures/adapter | Promiscuous live capture, UI-process full-file retention, raw-payload default | Retain packet workbench |
| Echolocate | Passive `arp -a` parsing and bounded latency context | Ping sweep by default, port/banner scanning, alerts, synthetic topology as observed fact | Candidate retirement after passive parity |
| NetworkMapper | No code dependency | ARP/nmap/CVE/risk/security scanning pipeline | Remain separate/manual-only |

## Provenance review oracle

For every imported file or adapted algorithm, record donor path and commit, new owner, license, behavior retained, behavior rejected, test coverage, and negative-requirement scan. Any ambiguous helper/scanner/payload/remediation coupling blocks the import.
