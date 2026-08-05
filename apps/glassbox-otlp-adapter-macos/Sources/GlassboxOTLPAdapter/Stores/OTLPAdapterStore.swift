import AppKit
import Foundation
import UniformTypeIdentifiers

@MainActor
final class OTLPAdapterStore: ObservableObject {
  @Published private(set) var phase: AdapterPhase = .idle
  @Published private(set) var endpoint = ""
  @Published private(set) var credential = ""
  @Published private(set) var destinationName = ""
  @Published private(set) var acceptedEvents: UInt64 = 0
  @Published private(set) var receipt: EvidenceReceipt?

  private let broker = BrokerProcess()
  private var destinationURL: URL?
  private var ownsDestination = false
  private var securityScopeActive = false

  var canStart: Bool {
    switch phase {
    case .idle, .completed, .failed: true
    default: false
    }
  }

  var canStop: Bool { phase == .listening }

  func startCapture() {
    guard canStart else { return }
    phase = .choosingDestination
    let panel = NSSavePanel()
    panel.title = "Save Glassbox Live Evidence"
    panel.message = "Choose where the completed, metadata-only evidence bundle will be saved."
    panel.nameFieldStringValue = "Glassbox Live Evidence.glassbox"
    panel.canCreateDirectories = true
    if let type = UTType(filenameExtension: "glassbox") {
      panel.allowedContentTypes = [type]
    }
    guard panel.runModal() == .OK, let url = panel.url else {
      phase = .idle
      return
    }
    beginCapture(to: url)
  }

  func stopCapture() {
    guard canStop else { return }
    phase = .stopping
    do {
      try broker.stop()
    } catch BrokerProcessError.notRunning {
      // Exit and completion delivery may already be in flight.
    } catch {
      fail(error.localizedDescription)
    }
  }

  func copyEndpoint() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(endpoint, forType: .string)
  }

  func copyCredential() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(credential, forType: .string)
  }

  private func beginCapture(to url: URL) {
    phase = .starting
    endpoint = ""
    acceptedEvents = 0
    receipt = nil
    destinationURL = url
    ownsDestination = false
    destinationName = url.lastPathComponent
    guard !FileManager.default.fileExists(atPath: url.path) else {
      fail("Choose a new destination so an existing evidence bundle is never overwritten.")
      return
    }
    securityScopeActive = url.startAccessingSecurityScopedResource()
    do {
      credential = try CredentialGenerator.makeHex()
      let session = "session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())"
      let source = "source_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())"
      let configuration = BrokerConfiguration(
        sessionID: session,
        sourceID: source,
        credential: credential
      )
      try broker.start(
        helperURL: try helperURL(),
        evidenceURL: url,
        configuration: configuration,
        onMessage: { [weak self] message in
          Task { @MainActor in self?.handle(message) }
        },
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

  private func handle(_ message: BrokerMessage) {
    switch message.type {
    case "ready":
      guard let bound = message.bound else {
        fail("The receiver returned an incomplete endpoint receipt.")
        return
      }
      endpoint = "tcp://\(bound)"
      phase = .listening
    case "complete":
      acceptedEvents = message.acceptedEvents ?? 0
      receipt = message.evidence
    case "rejected":
      fail("The receiver rejected the session (\(message.code ?? "unknown")).")
    default:
      fail("The receiver returned an unsupported protocol message.")
    }
  }

  private func handleExit(code: Int32, diagnostics: String) {
    defer { endSecurityScope() }
    let completed = receipt?.publishedToInheritedDescriptor == true
    if code == 0, completed {
      phase = .completed
      ownsDestination = false
    } else if case .failed = phase {
      return
    } else {
      removeOwnedDestination()
      fail("The receiver stopped before a valid bundle was complete. No evidence was published.")
    }
    credential = ""
    endpoint = ""
  }

  private func fail(_ message: String) {
    broker.terminate()
    removeOwnedDestination()
    phase = .failed(message)
    credential = ""
    endpoint = ""
    endSecurityScope()
  }

  private func removeOwnedDestination() {
    if ownsDestination, let destinationURL {
      try? FileManager.default.removeItem(at: destinationURL)
    }
    ownsDestination = false
  }

  private func endSecurityScope() {
    if securityScopeActive {
      destinationURL?.stopAccessingSecurityScopedResource()
    }
    securityScopeActive = false
  }

  private func helperURL() throws -> URL {
    let url = Bundle.main.bundleURL
      .appendingPathComponent("Contents", isDirectory: true)
      .appendingPathComponent("Helpers", isDirectory: true)
      .appendingPathComponent("glassbox-otlp-broker", isDirectory: false)
    guard FileManager.default.isExecutableFile(atPath: url.path) else {
      throw AdapterStoreError.missingBroker
    }
    return url
  }
}

enum AdapterStoreError: LocalizedError {
  case missingBroker

  var errorDescription: String? {
    "The signed OTLP receiver is missing from the adapter bundle."
  }
}
