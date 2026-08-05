import AppKit
import Foundation
import UniformTypeIdentifiers

@MainActor
final class ProcessAdapterStore: ObservableObject {
  @Published private(set) var phase: ProcessAdapterPhase = .ready
  @Published private(set) var candidates: [ProcessCandidate] = []
  @Published var selectedID: ProcessCandidate.ID?
  @Published private(set) var destinationName = ""
  @Published private(set) var receipt: ProcessEvidenceReceipt?

  private let process = ProcessBrokerProcess()
  private var destinationURL: URL?
  private var ownsDestination = false

  init() { refreshCandidates() }

  var canRefresh: Bool { phase == .ready || phase == .completed || isFailed }
  var canStart: Bool { canRefresh && selectedCandidate != nil }
  var canStop: Bool { phase == .capturing }
  var canCancel: Bool { phase == .capturing || phase == .stopping }

  private var isFailed: Bool { if case .failed = phase { true } else { false } }
  private var selectedCandidate: ProcessCandidate? {
    guard let selectedID else { return nil }
    return candidates.first(where: { $0.id == selectedID })
  }

  func refreshCandidates() {
    guard canRefresh || candidates.isEmpty else { return }
    let previous = selectedID
    candidates = ProcessCandidate.current()
    selectedID = candidates.contains(where: { $0.id == previous }) ? previous : candidates.first?.id
    if candidates.isEmpty { phase = .failed("No selectable running applications are available.") }
    else if isFailed { phase = .ready }
  }

  func startCapture() {
    guard canStart, let candidate = selectedCandidate else { return }
    guard candidate.isStillSelectedApplication else {
      phase = .failed("The selected application is no longer running.")
      refreshCandidates()
      return
    }
    phase = .choosingDestination
    let panel = NSSavePanel()
    panel.title = "Save Process Context Evidence"
    panel.message = "Choose a new file for the bounded, noncausal process resource bundle."
    panel.nameFieldStringValue = "Glassbox Process Context.glassbox"
    panel.canCreateDirectories = true
    if let type = UTType(filenameExtension: "glassbox") { panel.allowedContentTypes = [type] }
    guard panel.runModal() == .OK, let url = panel.url else {
      phase = .ready
      return
    }
    beginCapture(candidate: candidate, destination: url)
  }

  func stopCapture() {
    guard canStop else { return }
    phase = .stopping
    do { try process.stop() }
    catch { fail("The active capture could not be stopped safely.") }
  }

  func cancelCapture() {
    guard canCancel else { return }
    phase = .cancelling
    process.terminate()
    removeOwnedDestination()
  }

  private func beginCapture(candidate: ProcessCandidate, destination: URL) {
    guard !FileManager.default.fileExists(atPath: destination.path) else {
      phase = .failed("Choose a new destination so existing evidence is never overwritten.")
      return
    }
    phase = .capturing
    receipt = nil
    destinationURL = destination
    destinationName = destination.lastPathComponent
    ownsDestination = false
    do {
      let consent = try ProcessConsentGenerator.makeHex()
      let session = "process_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())"
      try process.start(
        helperURL: try helperURL(),
        evidenceURL: destination,
        candidate: candidate,
        captureSession: session,
        consentCapability: consent,
        onMessage: { [weak self] message in Task { @MainActor in self?.handle(message) } },
        onExit: { [weak self] code, diagnostics in
          Task { @MainActor in self?.handleExit(code: code, diagnostics: diagnostics) }
        })
      ownsDestination = true
    } catch {
      try? FileManager.default.removeItem(at: destination)
      fail(error.localizedDescription)
    }
  }

  private func handle(_ message: ProcessBrokerMessage) {
    guard phase != .cancelling else { return }
    switch message.type {
    case "evidence": receipt = message.evidence
    case "rejected": fail("The process adapter rejected the capture (\(message.code ?? "unknown")).")
    default: fail("The process adapter returned an unsupported protocol message.")
    }
  }

  private func handleExit(code: Int32, diagnostics: String) {
    if phase == .cancelling {
      removeOwnedDestination()
      phase = .ready
    } else if code == 0, receipt?.publishedToInheritedDescriptor == true {
      ownsDestination = false
      phase = .completed
    } else if case .failed = phase {
      return
    } else {
      removeOwnedDestination()
      fail("No valid process-context evidence was published.")
    }
  }

  private func fail(_ message: String) {
    process.terminate()
    removeOwnedDestination()
    phase = .failed(message)
  }

  private func removeOwnedDestination() {
    if ownsDestination, let destinationURL { try? FileManager.default.removeItem(at: destinationURL) }
    ownsDestination = false
  }

  private func helperURL() throws -> URL {
    let url = Bundle.main.bundleURL
      .appendingPathComponent("Contents", isDirectory: true)
      .appendingPathComponent("Helpers", isDirectory: true)
      .appendingPathComponent("glassbox-process-context-broker")
    guard FileManager.default.isExecutableFile(atPath: url.path) else {
      throw ProcessAdapterError.missingBroker
    }
    return url
  }
}

enum ProcessAdapterError: LocalizedError {
  case missingBroker
  var errorDescription: String? { "The signed process-context helper is missing." }
}
