import XCTest
@testable import GlassboxOTLPAdapter

final class AdapterModelsTests: XCTestCase {
  func testConfigurationKeepsAbsoluteBoundsAndDoesNotPutCredentialInEndpoint() throws {
    let configuration = BrokerConfiguration(
      sessionID: "session_test_001",
      sourceID: "source_test_001",
      credential: "credential-test-value-00000001"
    )
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(configuration)) as? [String: Any]
    )
    XCTAssertEqual(object["bind"] as? String, "127.0.0.1:0")
    XCTAssertEqual(object["max_frame_bytes"] as? Int, 1_048_576)
    XCTAssertEqual(object["max_events"] as? Int, 100_000)
    XCTAssertEqual(object["max_total_bytes"] as? Int, 268_435_456)
    XCTAssertEqual(object["max_events_per_second"] as? Int, 20_000)
    XCTAssertFalse((object["bind"] as? String)?.contains("credential") ?? true)
  }

  func testEvidenceReceiptRequiresExplicitPublicationState() throws {
    let data = Data(#"{"schema_version":"glassbox-live-evidence/v1","observations":2,"relations":1,"bundle_bytes":128,"bundle_sha256":"abc","published_to_inherited_descriptor":true}"#.utf8)
    let receipt = try JSONDecoder().decode(EvidenceReceipt.self, from: data)
    XCTAssertTrue(receipt.publishedToInheritedDescriptor)
    XCTAssertEqual(receipt.observations, 2)
    XCTAssertEqual(receipt.relations, 1)
  }
}
