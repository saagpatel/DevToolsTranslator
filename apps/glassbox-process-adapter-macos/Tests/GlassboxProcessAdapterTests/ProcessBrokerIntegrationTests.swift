import CryptoKit
import Foundation
import XCTest
@testable import GlassboxProcessAdapter

final class ProcessBrokerIntegrationTests: XCTestCase {
  func testControllerPublishesPrivateProcessBundleAndCoreReimportsIt() throws {
    let environment = ProcessInfo.processInfo.environment
    guard
      let helperPath = environment["GLASSBOX_PROCESS_BROKER_PATH"],
      let nativeBridgePath = environment["GLASSBOX_NATIVE_BRIDGE_PATH"]
    else { throw XCTSkip("Set signed process broker and native bridge paths.") }
    let temp = try ProcessTemporaryDirectory()
    defer { temp.remove() }
    let evidenceURL = temp.url.appendingPathComponent("process.glassbox")
    let consent = "swift-process-consent-capability-000001"
    let state = ProcessIntegrationState()
    let process = ProcessBrokerProcess()
    defer { process.terminate() }
    try process.start(
      helperURL: URL(fileURLWithPath: helperPath),
      evidenceURL: evidenceURL,
      candidate: ProcessCandidate(
        processIdentifier: ProcessInfo.processInfo.processIdentifier,
        bundleIdentifier: "com.glassbox.process-integration",
        displayName: "Integration host"),
      captureSession: "swift_process_integration_001",
      consentCapability: consent,
      intervalMilliseconds: 100,
      maximumSamples: 1,
      onMessage: { state.record($0) },
      onExit: { code, diagnostics in state.finish(code: code, diagnostics: diagnostics) })

    XCTAssertEqual(state.done.wait(timeout: .now() + 10), .success)
    let result = state.snapshot()
    let context = "messages: \(result.messageTypes), diagnostics: \(result.diagnostics)"
    XCTAssertEqual(result.exitCode, 0, context)
    XCTAssertTrue(result.diagnostics.isEmpty, context)
    let receipt = try XCTUnwrap(result.receipt)
    XCTAssertEqual(receipt.schemaVersion, "glassbox-process-evidence/v1")
    XCTAssertEqual(receipt.observations, 2)
    XCTAssertEqual(receipt.relations, 0)
    XCTAssertTrue(receipt.publishedToInheritedDescriptor)
    let evidence = try Data(contentsOf: evidenceURL)
    XCTAssertTrue(evidence.starts(with: Data("GLSBX001".utf8)))
    for prohibited in [consent, "process_id", "executable_path", "process_arguments", "username", "environment", "diskio", "network_activity"] {
      XCTAssertFalse(evidence.contains(Data(prohibited.utf8)), "retained prohibited value: \(prohibited)")
    }
    let core = try runProcessCoreImport(at: nativeBridgePath, evidence: evidence)
    XCTAssertEqual(core.schemaVersion, "glassbox-native-shell/v1")
    XCTAssertEqual(core.totalCount, 2)
    XCTAssertEqual(core.kernel.inserted, 2)
    XCTAssertEqual(core.kernel.relationCount, 0)
    XCTAssertEqual(core.unmarkedDropCount, 0)
    XCTAssertEqual(core.view.conclusion, "unknown")
    try writeProcessWorkflowReceipt(receipt: receipt, core: core)
  }
}

private final class ProcessIntegrationState: @unchecked Sendable {
  let done = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var receipt: ProcessEvidenceReceipt?
  private var exitCode: Int32?
  private var diagnostics = ""
  private var messageTypes: [String] = []

  func record(_ message: ProcessBrokerMessage) {
    lock.withCriticalSection {
      messageTypes.append(message.type)
      if message.type == "evidence" { receipt = message.evidence }
    }
  }

  func finish(code: Int32, diagnostics: String) {
    lock.withCriticalSection {
      exitCode = code
      self.diagnostics = diagnostics
    }
    done.signal()
  }

  func snapshot() -> (
    receipt: ProcessEvidenceReceipt?, exitCode: Int32?, diagnostics: String, messageTypes: [String]
  ) { lock.withCriticalSection { (receipt, exitCode, diagnostics, messageTypes) } }
}

private func runProcessCoreImport(
  at bridgePath: String, evidence: Data
) throws -> ProcessCoreImportReceipt {
  let digest = SHA256.hash(data: evidence).map { String(format: "%02x", $0) }.joined()
  let process = Process()
  process.executableURL = URL(fileURLWithPath: bridgePath)
  process.arguments = ["--import", "glassbox", digest, "process_adapter_reimport_001"]
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
  let errors = diagnostics.fileHandleForReading.readDataToEndOfFile()
  guard process.terminationStatus == 0, errors.isEmpty else {
    throw ProcessWorkflowError.coreImportFailed(String(decoding: errors, as: UTF8.self))
  }
  return try JSONDecoder().decode(ProcessCoreImportReceipt.self, from: payload)
}

private struct ProcessCoreImportReceipt: Decodable {
  struct Kernel: Decodable {
    let inserted: Int
    let relationCount: Int
    enum CodingKeys: String, CodingKey { case inserted; case relationCount = "relation_count" }
  }
  struct View: Decodable { let conclusion: String }
  let schemaVersion: String
  let kernel: Kernel
  let totalCount: Int
  let unmarkedDropCount: Int
  let view: View
  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case kernel, view
    case totalCount = "total_count"
    case unmarkedDropCount = "unmarked_drop_count"
  }
}

private func writeProcessWorkflowReceipt(
  receipt: ProcessEvidenceReceipt, core: ProcessCoreImportReceipt
) throws {
  guard let path = ProcessInfo.processInfo.environment["GLASSBOX_PROCESS_WORKFLOW_RECEIPT"] else {
    return
  }
  let object: [String: Any] = [
    "schema_version": "glassbox-process-adapter-workflow/v1",
    "ok": true,
    "consent_transport": "inherited_descriptor",
    "configuration_transport": "stdin",
    "evidence_schema_version": receipt.schemaVersion,
    "observations": receipt.observations,
    "relations": receipt.relations,
    "published_to_inherited_descriptor": receipt.publishedToInheritedDescriptor,
    "pid_path_arguments_user_environment_files_disk_and_network_excluded": true,
    "consent_capability_excluded": true,
    "core_reimport_schema_version": core.schemaVersion,
    "core_reimport_total_count": core.totalCount,
    "core_reimport_inserted": core.kernel.inserted,
    "core_reimport_relation_count": core.kernel.relationCount,
    "core_reimport_unmarked_drop_count": core.unmarkedDropCount,
    "core_conclusion": core.view.conclusion,
  ]
  let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
  try data.write(to: URL(fileURLWithPath: path), options: [.atomic])
}

private struct ProcessTemporaryDirectory {
  let url: URL
  init() throws {
    url = FileManager.default.temporaryDirectory
      .appendingPathComponent("glassbox-process-adapter-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
  }
  func remove() { try? FileManager.default.removeItem(at: url) }
}

private enum ProcessWorkflowError: Error { case coreImportFailed(String) }

private extension NSLock {
  func withCriticalSection<T>(_ body: () -> T) -> T {
    lock()
    defer { unlock() }
    return body()
  }
}
