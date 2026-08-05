import AppKit
import Foundation
import UniformTypeIdentifiers

@MainActor
final class PassiveAdapterStore: ObservableObject {
  @Published private(set) var phase: PassivePhase = .idle
  @Published private(set) var destinationName = ""
  @Published private(set) var receipt: PassiveEvidenceReceipt?

  private let process = PassiveBrokerProcess()
  private var destinationURL: URL?
  private var ownsDestination = false
  private var securityScopeActive = false

  var canStart: Bool {
    switch phase {
    case .idle, .completed, .failed: true
    default: false
    }
  }

  var canCancel: Bool { phase == .capturing }

  func startCapture() {
    guard canStart else { return }
    phase = .choosingDestination
    let panel = NSSavePanel()
    panel.title = "Save Passive Context Evidence"
    panel.message = "Choose where the metadata-only, noncausal evidence bundle will be saved."
    panel.nameFieldStringValue = "Glassbox Passive Context.glassbox"
    panel.canCreateDirectories = true
    if let type = UTType(filenameExtension: "glassbox") { panel.allowedContentTypes = [type] }
    guard panel.runModal() == .OK, let url = panel.url else {
      phase = .idle
      return
    }
    beginCapture(to: url)
  }

  func cancelCapture() {
    guard canCancel else { return }
    phase = .cancelling
    process.terminate()
    removeOwnedDestination()
    endSecurityScope()
  }

  private func beginCapture(to url: URL) {
    phase = .capturing
    receipt = nil
    destinationURL = url
    destinationName = url.lastPathComponent
    ownsDestination = false
    guard !FileManager.default.fileExists(atPath: url.path) else {
      fail("Choose a new destination so existing evidence is never overwritten.")
      return
    }
    securityScopeActive = url.startAccessingSecurityScopedResource()
    do {
      let consent = try ConsentGenerator.makeHex()
      let session = "passive_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())"
      try process.start(
        helperURL: try helperURL(),
        evidenceURL: url,
        captureSession: session,
        consentCapability: consent,
        input: .liveSnapshot,
        onMessage: { [weak self] message in Task { @MainActor in self?.handle(message) } },
        onExit: { [weak self] code, diagnostics in
          Task { @MainActor in self?.handleExit(code: code, diagnostics: diagnostics) }
        }
      )
      ownsDestination = true
    } catch {
      try? FileManager.default.removeItem(at: url)
      ownsDestination = false
      fail(error.localizedDescription)
    }
  }

  private func handle(_ message: PassiveBrokerMessage) {
    guard phase != .cancelling else { return }
    switch message.type {
    case "evidence": receipt = message.evidence
    case "rejected": fail("The passive adapter rejected the request (\(message.code ?? "unknown")).")
    default: fail("The passive adapter returned an unsupported protocol message.")
    }
  }

  private func handleExit(code: Int32, diagnostics: String) {
    defer { endSecurityScope() }
    if phase == .cancelling {
      removeOwnedDestination()
      phase = .idle
    } else if code == 0, receipt?.publishedToInheritedDescriptor == true {
      ownsDestination = false
      phase = .completed
    } else if case .failed = phase {
      return
    } else {
      removeOwnedDestination()
      fail("No valid passive-context evidence was published.")
    }
  }

  private func fail(_ message: String) {
    process.terminate()
    removeOwnedDestination()
    phase = .failed(message)
    endSecurityScope()
  }

  private func removeOwnedDestination() {
    if ownsDestination, let destinationURL { try? FileManager.default.removeItem(at: destinationURL) }
    ownsDestination = false
  }

  private func endSecurityScope() {
    if securityScopeActive { destinationURL?.stopAccessingSecurityScopedResource() }
    securityScopeActive = false
  }

  private func helperURL() throws -> URL {
    let url = Bundle.main.bundleURL
      .appendingPathComponent("Contents/Helpers/glassbox-passive-context-broker")
    guard FileManager.default.isExecutableFile(atPath: url.path) else {
      throw PassiveAdapterError.missingBroker
    }
    return url
  }
}

enum PassiveAdapterError: LocalizedError {
  case missingBroker
  var errorDescription: String? { "The signed passive-context helper is missing." }
}
