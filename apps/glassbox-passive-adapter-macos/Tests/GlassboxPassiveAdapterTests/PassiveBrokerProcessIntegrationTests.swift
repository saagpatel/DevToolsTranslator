import CryptoKit
import Foundation
import XCTest
@testable import GlassboxPassiveAdapter

final class PassiveBrokerProcessIntegrationTests: XCTestCase {
  func testSwiftControllerPublishesMetadataOnlyBundleAndCoreReimportsIt() throws {
    let environment = ProcessInfo.processInfo.environment
    guard
      let helperPath = environment["GLASSBOX_PASSIVE_BROKER_PATH"],
      let fixturePath = environment["GLASSBOX_PASSIVE_FIXTURE_PATH"],
      let nativeBridgePath = environment["GLASSBOX_NATIVE_BRIDGE_PATH"]
    else {
      throw XCTSkip("Set the signed passive broker, fixture, and native bridge paths.")
    }
    let temp = try TemporaryDirectory()
    defer { temp.remove() }
    let evidenceURL = temp.url.appendingPathComponent("passive.glassbox")
    let fixture = try Data(contentsOf: URL(fileURLWithPath: fixturePath))
    let consent = "swift-passive-consent-capability-000001"
    let state = PassiveIntegrationState()
    let process = PassiveBrokerProcess()
    defer { process.terminate() }

    try process.start(
      helperURL: URL(fileURLWithPath: helperPath),
      evidenceURL: evidenceURL,
      captureSession: "swift_passive_integration_001",
      consentCapability: consent,
      input: .fixture(fixture),
      onMessage: { state.record($0) },
      onExit: { code, diagnostics in state.finish(code: code, diagnostics: diagnostics) }
    )

    XCTAssertEqual(state.done.wait(timeout: .now() + 10), .success)
    let result = state.snapshot()
    let context = "messages: \(result.messageTypes), diagnostics: \(result.diagnostics)"
    XCTAssertEqual(result.exitCode, 0, context)
    XCTAssertTrue(result.diagnostics.isEmpty, context)
    let receipt = try XCTUnwrap(result.receipt)
    XCTAssertEqual(receipt.schemaVersion, "glassbox-passive-evidence/v1")
    XCTAssertEqual(receipt.observations, 3)
    XCTAssertEqual(receipt.relations, 0)
    XCTAssertTrue(receipt.publishedToInheritedDescriptor)

    let evidence = try Data(contentsOf: evidenceURL)
    XCTAssertTrue(evidence.starts(with: Data("GLSBX001".utf8)))
    for forbidden in [consent, "192.0.2.1", "192.0.2.2", "aa:bb:cc:dd:ee:1", "en0"] {
      XCTAssertFalse(evidence.contains(Data(forbidden.utf8)), "retained forbidden value: \(forbidden)")
    }
    let coreImport = try runCoreImport(at: nativeBridgePath, evidence: evidence)
    XCTAssertEqual(coreImport.schemaVersion, "glassbox-native-shell/v1")
    XCTAssertEqual(coreImport.totalCount, 3)
    XCTAssertEqual(coreImport.kernel.inserted, 3)
    XCTAssertEqual(coreImport.kernel.relationCount, 0)
    XCTAssertEqual(coreImport.unmarkedDropCount, 0)
    XCTAssertEqual(coreImport.view.conclusion, "unknown")

    try writeWorkflowReceipt(evidenceReceipt: receipt, coreImport: coreImport)
  }
}

private final class PassiveIntegrationState: @unchecked Sendable {
  let done = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var receipt: PassiveEvidenceReceipt?
  private var exitCode: Int32?
  private var diagnostics = ""
  private var messageTypes: [String] = []

  func record(_ message: PassiveBrokerMessage) {
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
    receipt: PassiveEvidenceReceipt?, exitCode: Int32?, diagnostics: String, messageTypes: [String]
  ) {
    lock.withCriticalSection { (receipt, exitCode, diagnostics, messageTypes) }
  }
}

private func runCoreImport(at bridgePath: String, evidence: Data) throws -> PassiveCoreImportReceipt {
  let digest = SHA256.hash(data: evidence).map { String(format: "%02x", $0) }.joined()
  let process = Process()
  process.executableURL = URL(fileURLWithPath: bridgePath)
  process.arguments = ["--import", "glassbox", digest, "passive_adapter_reimport_001"]
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
  let errorBytes = diagnostics.fileHandleForReading.readDataToEndOfFile()
  guard process.terminationStatus == 0, errorBytes.isEmpty else {
    throw PassiveWorkflowError.coreImportFailed(String(decoding: errorBytes, as: UTF8.self))
  }
  return try JSONDecoder().decode(PassiveCoreImportReceipt.self, from: payload)
}

private struct PassiveCoreImportReceipt: Decodable {
  struct KernelReceipt: Decodable {
    let inserted: Int
    let relationCount: Int

    enum CodingKeys: String, CodingKey {
      case inserted
      case relationCount = "relation_count"
    }
  }

  struct ViewReceipt: Decodable { let conclusion: String }

  let schemaVersion: String
  let kernel: KernelReceipt
  let totalCount: Int
  let unmarkedDropCount: Int
  let view: ViewReceipt

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case kernel, view
    case totalCount = "total_count"
    case unmarkedDropCount = "unmarked_drop_count"
  }
}

private func writeWorkflowReceipt(
  evidenceReceipt: PassiveEvidenceReceipt,
  coreImport: PassiveCoreImportReceipt
) throws {
  guard let path = ProcessInfo.processInfo.environment["GLASSBOX_PASSIVE_WORKFLOW_RECEIPT"] else {
    return
  }
  let receipt: [String: Any] = [
    "schema_version": "glassbox-passive-adapter-workflow/v1",
    "ok": true,
    "consent_transport": "inherited_descriptor",
    "request_omits_consent_capability": true,
    "evidence_schema_version": evidenceReceipt.schemaVersion,
    "observations": evidenceReceipt.observations,
    "relations": evidenceReceipt.relations,
    "bundle_sha256": evidenceReceipt.bundleSHA256,
    "published_to_inherited_descriptor": evidenceReceipt.publishedToInheritedDescriptor,
    "addresses_link_ids_and_interfaces_excluded": true,
    "consent_capability_excluded": true,
    "core_reimport_schema_version": coreImport.schemaVersion,
    "core_reimport_total_count": coreImport.totalCount,
    "core_reimport_inserted": coreImport.kernel.inserted,
    "core_reimport_relation_count": coreImport.kernel.relationCount,
    "core_reimport_unmarked_drop_count": coreImport.unmarkedDropCount,
    "core_conclusion": coreImport.view.conclusion,
  ]
  let data = try JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted, .sortedKeys])
  try data.write(to: URL(fileURLWithPath: path), options: [.atomic])
}

private struct TemporaryDirectory {
  let url: URL

  init() throws {
    url = FileManager.default.temporaryDirectory
      .appendingPathComponent("glassbox-passive-adapter-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
  }

  func remove() { try? FileManager.default.removeItem(at: url) }
}

private enum PassiveWorkflowError: Error { case coreImportFailed(String) }

private extension NSLock {
  func withCriticalSection<T>(_ body: () -> T) -> T {
    lock()
    defer { unlock() }
    return body()
  }
}
