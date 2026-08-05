import CryptoKit
import Foundation
import XCTest
@testable import GlassboxOTLPAdapter

final class BrokerProcessIntegrationTests: XCTestCase {
  func testSignedReferenceSourcePublishesKernelValidatedBundleThroughSwiftController() throws {
    guard
      let helperPath = ProcessInfo.processInfo.environment["GLASSBOX_OTLP_BROKER_PATH"],
      let sourcePath = ProcessInfo.processInfo.environment["GLASSBOX_REFERENCE_SOURCE_PATH"],
      let nativeBridgePath = ProcessInfo.processInfo.environment["GLASSBOX_NATIVE_BRIDGE_PATH"]
    else {
      throw XCTSkip("Set the signed broker and reference-source paths to run the workflow integration.")
    }
    let temp = try TemporaryDirectory()
    defer { temp.remove() }
    let evidenceURL = temp.url.appendingPathComponent("live.glassbox")
    let credential = "swift-integration-credential-000001"
    let state = IntegrationState()
    let process = BrokerProcess()
    defer { process.terminate() }
    try process.start(
      helperURL: URL(fileURLWithPath: helperPath),
      evidenceURL: evidenceURL,
      configuration: BrokerConfiguration(
        sessionID: "swift_adapter_integration_001",
        sourceID: "swift_adapter_source_001",
        credential: credential
      ),
      onMessage: { state.record($0) },
      onExit: { code, diagnostics in state.finish(code: code, diagnostics: diagnostics) }
    )

    XCTAssertEqual(state.ready.wait(timeout: .now() + 10), .success)
    let bound = try XCTUnwrap(state.snapshot().bound)
    let sourceReceipt = try runReferenceSource(
      at: sourcePath,
      endpoint: bound,
      credential: credential
    )
    XCTAssertEqual(sourceReceipt.schemaVersion, "glassbox-reference-instrumented-source/v1")
    XCTAssertEqual(sourceReceipt.framesSent, 1)
    XCTAssertTrue(sourceReceipt.endpointWasLoopback)
    XCTAssertFalse(sourceReceipt.credentialExposed)
    do {
      try process.stop()
    } catch BrokerProcessError.notRunning {
      // Source EOF can complete the helper before explicit stop reaches it.
    }
    let completion = state.done.wait(timeout: .now() + 10)
    if completion == .timedOut {
      process.terminate()
      _ = state.done.wait(timeout: .now() + 2)
    }
    let result = state.snapshot()
    let context = "messages: \(result.messageTypes), diagnostics: \(result.diagnostics)"
    XCTAssertEqual(completion, .success, context)
    XCTAssertEqual(result.exitCode, 0, context)
    XCTAssertEqual(result.receipt?.schemaVersion, "glassbox-live-evidence/v1")
    XCTAssertEqual(result.receipt?.observations, 2)
    XCTAssertEqual(result.receipt?.relations, 0)
    XCTAssertTrue(result.receipt?.publishedToInheritedDescriptor ?? false)
    let bytes = try Data(contentsOf: evidenceURL)
    XCTAssertTrue(bytes.starts(with: Data("GLSBX001".utf8)))
    XCTAssertFalse(bytes.contains(Data(credential.utf8)))
    XCTAssertFalse(bytes.contains(Data("private-reference-operation".utf8)))
    XCTAssertFalse(bytes.contains(Data("reference-secret-do-not-retain".utf8)))
    XCTAssertTrue(result.diagnostics.isEmpty, context)
    let coreImport = try runCoreImport(at: nativeBridgePath, evidence: bytes)
    XCTAssertEqual(coreImport.schemaVersion, "glassbox-native-shell/v1")
    XCTAssertEqual(coreImport.totalCount, 2)
    XCTAssertEqual(coreImport.kernel.inserted, 2)
    XCTAssertEqual(coreImport.kernel.total, 2)
    XCTAssertEqual(coreImport.unmarkedDropCount, 0)
    let workflowOK = completion == .success
      && result.exitCode == 0
      && result.receipt?.schemaVersion == "glassbox-live-evidence/v1"
      && result.receipt?.observations == 2
      && result.receipt?.relations == 0
      && result.receipt?.publishedToInheritedDescriptor == true
      && bytes.starts(with: Data("GLSBX001".utf8))
      && !bytes.contains(Data(credential.utf8))
      && !bytes.contains(Data("private-reference-operation".utf8))
      && !bytes.contains(Data("reference-secret-do-not-retain".utf8))
      && sourceReceipt.schemaVersion == "glassbox-reference-instrumented-source/v1"
      && sourceReceipt.framesSent == 1
      && sourceReceipt.bytesSent > 0
      && sourceReceipt.endpointWasLoopback
      && !sourceReceipt.credentialExposed
      && coreImport.schemaVersion == "glassbox-native-shell/v1"
      && coreImport.totalCount == 2
      && coreImport.kernel.inserted == 2
      && coreImport.kernel.total == 2
      && coreImport.unmarkedDropCount == 0
      && result.diagnostics.isEmpty
    guard workflowOK else { throw ProbeError.workflowInvalid }
    try writeWorkflowReceipt(
      sourceReceipt: sourceReceipt,
      evidenceReceipt: try XCTUnwrap(result.receipt),
      coreImport: coreImport
    )
  }
}

private final class IntegrationState: @unchecked Sendable {
  let done = DispatchSemaphore(value: 0)
  let ready = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var bound: String?
  private var receipt: EvidenceReceipt?
  private var exitCode: Int32?
  private var diagnostics = ""
  private var messageTypes: [String] = []

  func record(_ message: BrokerMessage) {
    lock.withCriticalSection {
      messageTypes.append(message.type)
      if message.type == "ready" { bound = message.bound }
      if message.type == "complete" { receipt = message.evidence }
    }
    if message.type == "ready" { ready.signal() }
  }

  func finish(code: Int32, diagnostics: String) {
    lock.withCriticalSection {
      exitCode = code
      self.diagnostics = diagnostics
    }
    done.signal()
  }

  func snapshot() -> (
    bound: String?, receipt: EvidenceReceipt?, exitCode: Int32?,
    diagnostics: String, messageTypes: [String]
  ) {
    lock.withCriticalSection { (bound, receipt, exitCode, diagnostics, messageTypes) }
  }
}

private func runReferenceSource(
  at sourcePath: String,
  endpoint: String,
  credential: String
) throws -> SourceReceipt {
  let configuration: [String: Any] = [
    "protocol_version": 1,
    "endpoint": endpoint,
    "session_id": "swift_adapter_integration_001",
    "source_id": "swift_adapter_source_001",
    "source_epoch": 1,
    "credential": credential,
    "event_count": 1,
  ]
  var encoded = try JSONSerialization.data(withJSONObject: configuration, options: [.sortedKeys])
  encoded.append(0x0A)
  let producer = Process()
  producer.executableURL = URL(fileURLWithPath: sourcePath)
  let input = Pipe()
  let output = Pipe()
  let diagnostics = Pipe()
  producer.standardInput = input
  producer.standardOutput = output
  producer.standardError = diagnostics
  try producer.run()
  input.fileHandleForReading.closeFile()
  try input.fileHandleForWriting.write(contentsOf: encoded)
  input.fileHandleForWriting.closeFile()
  producer.waitUntilExit()
  let outputBytes = output.fileHandleForReading.readDataToEndOfFile()
  let diagnosticBytes = diagnostics.fileHandleForReading.readDataToEndOfFile()
  guard producer.terminationStatus == 0 else {
    throw ProbeError.externalProducerFailed(
      String(decoding: diagnosticBytes, as: UTF8.self)
    )
  }
  guard
    !outputBytes.contains(Data(credential.utf8)),
    !diagnosticBytes.contains(Data(credential.utf8))
  else {
    throw ProbeError.credentialExposed
  }
  return try JSONDecoder().decode(SourceReceipt.self, from: outputBytes)
}

private struct SourceReceipt: Decodable {
  let schemaVersion: String
  let framesSent: UInt16
  let bytesSent: UInt64
  let endpointWasLoopback: Bool
  let credentialExposed: Bool

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case framesSent = "frames_sent"
    case bytesSent = "bytes_sent"
    case endpointWasLoopback = "endpoint_was_loopback"
    case credentialExposed = "credential_exposed"
  }
}

private func runCoreImport(at bridgePath: String, evidence: Data) throws -> CoreImportReceipt {
  let digest = SHA256.hash(data: evidence).map { String(format: "%02x", $0) }.joined()
  let process = Process()
  process.executableURL = URL(fileURLWithPath: bridgePath)
  process.arguments = ["--import", "glassbox", digest, "reference_reimport_001"]
  let input = Pipe()
  let output = Pipe()
  let diagnostics = Pipe()
  process.standardInput = input
  process.standardOutput = output
  process.standardError = diagnostics
  try process.run()
  input.fileHandleForReading.closeFile()
  try input.fileHandleForWriting.write(contentsOf: evidence)
  input.fileHandleForWriting.closeFile()
  process.waitUntilExit()
  let payload = output.fileHandleForReading.readDataToEndOfFile()
  let diagnosticBytes = diagnostics.fileHandleForReading.readDataToEndOfFile()
  guard process.terminationStatus == 0, diagnosticBytes.isEmpty else {
    throw ProbeError.coreImportFailed(String(decoding: diagnosticBytes, as: UTF8.self))
  }
  guard
    !payload.contains(Data("private-reference-operation".utf8)),
    !payload.contains(Data("reference-secret-do-not-retain".utf8))
  else {
    throw ProbeError.privateContentExposed
  }
  return try JSONDecoder().decode(CoreImportReceipt.self, from: payload)
}

private struct CoreImportReceipt: Decodable {
  struct KernelReceipt: Decodable {
    let inserted: Int
    let total: Int
  }

  let schemaVersion: String
  let kernel: KernelReceipt
  let totalCount: Int
  let unmarkedDropCount: Int

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case kernel
    case totalCount = "total_count"
    case unmarkedDropCount = "unmarked_drop_count"
  }
}

private func writeWorkflowReceipt(
  sourceReceipt: SourceReceipt,
  evidenceReceipt: EvidenceReceipt,
  coreImport: CoreImportReceipt
) throws {
  guard let path = ProcessInfo.processInfo.environment["GLASSBOX_REFERENCE_WORKFLOW_RECEIPT"] else {
    return
  }
  let receipt: [String: Any] = [
    "schema_version": "glassbox-reference-instrumented-workflow/v1",
    "ok": true,
    "source_schema_version": sourceReceipt.schemaVersion,
    "frames_sent": sourceReceipt.framesSent,
    "source_bytes_sent": sourceReceipt.bytesSent,
    "endpoint_was_loopback": sourceReceipt.endpointWasLoopback,
    "credential_exposed": sourceReceipt.credentialExposed,
    "evidence_schema_version": evidenceReceipt.schemaVersion,
    "observations": evidenceReceipt.observations,
    "relations": evidenceReceipt.relations,
    "bundle_sha256": evidenceReceipt.bundleSHA256,
    "published_to_inherited_descriptor": evidenceReceipt.publishedToInheritedDescriptor,
    "raw_private_content_excluded": true,
    "core_reimport_schema_version": coreImport.schemaVersion,
    "core_reimport_total_count": coreImport.totalCount,
    "core_reimport_inserted": coreImport.kernel.inserted,
    "core_reimport_unmarked_drop_count": coreImport.unmarkedDropCount,
  ]
  let data = try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
  try data.write(to: URL(fileURLWithPath: path), options: [.atomic])
}

private struct TemporaryDirectory {
  let url: URL

  init() throws {
    url = FileManager.default.temporaryDirectory
      .appendingPathComponent("glassbox-swift-adapter-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
  }

  func remove() { try? FileManager.default.removeItem(at: url) }
}

private enum ProbeError: Error {
  case externalProducerFailed(String)
  case credentialExposed
  case workflowInvalid
  case coreImportFailed(String)
  case privateContentExposed
}

private extension NSLock {
  func withCriticalSection<T>(_ body: () -> T) -> T {
    lock()
    defer { unlock() }
    return body()
  }
}
