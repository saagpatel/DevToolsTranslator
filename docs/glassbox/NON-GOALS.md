# Glassbox Non-goals And Permission Ceiling

Status: accepted for Gate 0 review
Owner: product authority
Test oracle: `NEGATIVE-REQUIREMENTS-CI.md`

The Glassbox core and MVP distribution contain no:

- LaunchDaemon, LaunchAgent, privileged helper, root installer, or root post-install script.
- `/dev/bpf` permission mutation, promiscuous live capture, ARP spoofing, or IP forwarding.
- Network Extension, Endpoint Security, packet-tunnel, content-filter, or DNS-proxy entitlement.
- MITM certificate, proxy-setting, or TLS-decryption installer.
- Accessibility, Input Monitoring, Screen Recording, Apple Events, Full Disk Access, microphone, or global input monitoring.
- Active port/vulnerability scanning, firewall, EDR, VPN, process killing, or automated remediation.
- Automatic cloud, analytics, crash, telemetry, or LLM upload of evidence.
- Dashboard-first home screen or general metrics-monitoring product.
- ProofOS, SafeForge, or unrelated operating-layer integration.

Privileged capture is not a deferred Glassbox phase. It requires a separate future product RFC, benchmark evidence of necessity, a new security review, a separate artifact boundary, and explicit approval.

## Failure behavior

Any prohibited dependency, entitlement, installer asset, script token, generated plist, bundled helper, runtime permission request, or residue blocks build promotion and release. There is no warning-only mode.

## Rollback

Remove the offending dependency or adapter and regenerate the entitlement/bundle inventory. Do not weaken the rule to accommodate donor code.
