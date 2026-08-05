import AppKit
import Foundation
import UniformTypeIdentifiers

@MainActor
final class InvestigationStore: ObservableObject {
  private struct PendingProbeRender {
    let token: UUID
    let code: String
    let started: ContinuousClock.Instant
    let continuation: CheckedContinuation<Double?, Never>
  }

  @Published private(set) var payload: NativeShellPayload?
  @Published private(set) var loadError: NativeShellError?
  @Published var selectedID = "e7"
  @Published var mode: WorkspaceMode = .timeline
  @Published var exportPresented = false
  @Published var searchText = ""
  @Published var enabledSources = Set<String>()
  @Published private(set) var isImporting = false
  @Published private(set) var isSamplingResources = false
  @Published private(set) var resourceSamplerStatus = "Idle"
  @Published var importErrorMessage: String?
  private let resourceSampler = ResourceSamplerController()
  private var interactionProbeStarted = false
  private var pendingProbeRender: PendingProbeRender?

  init(service: RustEvidenceService? = try? RustEvidenceService()) {
    guard let service else {
      loadError = .helperUnavailable
      return
    }
    do {
      let loaded: NativeShellPayload
      if CommandLine.arguments.contains("--glassbox-resource-sampler-probe") {
        loaded = try service.loadResourceSample(
          stopInput: FileHandle.standardInput,
          captureSession: UUID(), intervalMilliseconds: 100, maximumSamples: 2)
      } else if CommandLine.arguments.contains("--glassbox-import-probe") {
        let environment = ProcessInfo.processInfo.environment
        guard let rawFormat = environment["GLASSBOX_IMPORT_FORMAT"],
          let format = EvidenceImportFormat(rawValue: rawFormat),
          let sha256 = environment["GLASSBOX_SOURCE_SHA256"]
        else { throw NativeShellError.invalidImportProbe }
        let selected = SelectedArtifactHasher.HashedRegularFile(
          handle: FileHandle.standardInput, sha256: sha256, size: 0)
        defer { try? selected.handle.close() }
        loaded = try service.loadImport(
          selected: selected, format: format, captureSession: UUID())
      } else {
        loaded = try service.load()
      }
      apply(loaded)
    } catch let error as NativeShellError {
      loadError = error
    } catch {
      loadError = .helperFailed(error.localizedDescription)
    }
  }

  var selectedRow: EvidenceTableRow? {
    payload?.view.evidenceTable.first(where: { $0.id == selectedID })
  }

  var filteredRows: [EvidenceTableRow] {
    guard let rows = payload?.view.evidenceTable else { return [] }
    return rows.filter { row in
      enabledSources.contains(row.source)
        && (searchText.isEmpty
          || [row.label, row.actor, row.source, row.nativeLocator].contains {
            $0.localizedCaseInsensitiveContains(searchText)
          })
    }
  }

  func toggleSource(_ source: String) {
    if enabledSources.contains(source) {
      enabledSources.remove(source)
    } else {
      enabledSources.insert(source)
    }
  }

  func importEvidence() async {
    guard !isImporting, !isSamplingResources else { return }
    let panel = NSOpenPanel()
    panel.title = "Import evidence"
    panel.message = "Select a HAR, OTLP JSONL, PCAP, PCAPNG, or Glassbox evidence bundle."
    panel.prompt = "Import"
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.allowedContentTypes = ["har", "jsonl", "ndjson", "pcap", "pcapng", "glassbox"]
      .compactMap { UTType(filenameExtension: $0) }
    guard panel.runModal() == .OK, let url = panel.url else { return }
    guard let format = EvidenceImportFormat.resolve(url) else {
      importErrorMessage = "That evidence format is not supported."
      return
    }
    let accessed = url.startAccessingSecurityScopedResource()
    defer { if accessed { url.stopAccessingSecurityScopedResource() } }
    isImporting = true
    importErrorMessage = nil
    defer { isImporting = false }
    do {
      let selected = try SelectedArtifactHasher.openAndHash(
        file: url, maximumBytes: RustEvidenceService.maximumImportBytes)
      let service = try RustEvidenceService()
      let loaded = try await Task.detached(priority: .userInitiated) {
        defer { try? selected.handle.close() }
        return try service.loadImport(
          selected: selected, format: format, captureSession: UUID())
      }.value
      apply(loaded)
    } catch let error as LocalizedError {
      importErrorMessage = error.errorDescription ?? "The evidence import was rejected."
    } catch {
      importErrorMessage = "The evidence import was rejected."
    }
  }

  func toggleResourceSampler() {
    if isSamplingResources {
      resourceSamplerStatus = "Stopping…"
      resourceSampler.stop()
      return
    }
    guard !isImporting else { return }
    isSamplingResources = true
    resourceSamplerStatus = "Sampling system resources (30 second maximum)…"
    importErrorMessage = nil
    let service: RustEvidenceService
    do {
      service = try RustEvidenceService()
    } catch let error as NativeShellError {
      finishResourceSampler(with: .failure(error))
      return
    } catch {
      finishResourceSampler(with: .failure(.helperFailed("launch failed")))
      return
    }
    let controller = resourceSampler
    controller.arm()
    Task { @MainActor [weak self] in
      do {
        let loaded = try await Task.detached(priority: .userInitiated) {
          try controller.sample(service: service, captureSession: UUID())
        }.value
        self?.finishResourceSampler(with: .success(loaded))
      } catch let error as NativeShellError {
        self?.finishResourceSampler(with: .failure(error))
      } catch {
        self?.finishResourceSampler(with: .failure(.helperFailed("sampling failed")))
      }
    }
  }

  private func finishResourceSampler(with result: Result<NativeShellPayload, NativeShellError>) {
    isSamplingResources = false
    resourceSamplerStatus = "Idle"
    switch result {
    case .success(let loaded): apply(loaded)
    case .failure(let error):
      importErrorMessage = error.localizedDescription
    }
  }

  private func apply(_ loaded: NativeShellPayload) {
    payload = loaded
    enabledSources = Set(loaded.view.scope)
    selectedID = loaded.view.evidenceTable[0].id
    searchText = ""
  }

  func measureProbeRender(code: String, action: () -> Void) async -> Double? {
    guard pendingProbeRender == nil else { return nil }
    let token = UUID()
    return await withCheckedContinuation { continuation in
      pendingProbeRender = PendingProbeRender(
        token: token,
        code: code,
        started: ContinuousClock().now,
        continuation: continuation
      )
      action()
      Task { @MainActor [weak self] in
        try? await Task.sleep(for: .seconds(2))
        self?.expireProbeRender(token: token)
      }
    }
  }

  func acknowledgeProbeRender(code: String) {
    guard let pending = pendingProbeRender, pending.code == code else { return }
    pendingProbeRender = nil
    let duration = pending.started.duration(to: ContinuousClock().now).components
    let milliseconds =
      Double(duration.seconds) * 1_000 + Double(duration.attoseconds) / 1_000_000_000_000_000
    pending.continuation.resume(returning: (milliseconds * 1_000).rounded() / 1_000)
  }

  private func expireProbeRender(token: UUID) {
    guard let pending = pendingProbeRender, pending.token == token else { return }
    pendingProbeRender = nil
    pending.continuation.resume(returning: nil)
  }

  func runInteractionProbeIfRequested() async {
    guard
      let flagIndex = CommandLine.arguments.firstIndex(of: "--glassbox-interaction-probe"),
      CommandLine.arguments.indices.contains(flagIndex + 1),
      !interactionProbeStarted,
      payload != nil
    else { return }
    let probeID = CommandLine.arguments[flagIndex + 1]
    guard !probeID.isEmpty, !probeID.hasPrefix("--") else { return }
    interactionProbeStarted = true
    let result = await NativeInteractionProbe.run(store: self)
    NSApp.windows.first?.title = "Glassbox probe result \(probeID) \(result.base64URL())"
  }
}
