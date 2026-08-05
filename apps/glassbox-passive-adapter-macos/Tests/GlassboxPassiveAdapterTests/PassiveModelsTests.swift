import Foundation
import XCTest
@testable import GlassboxPassiveAdapter

final class PassiveModelsTests: XCTestCase {
  func testEvidenceReceiptRequiresExplicitPublicationState() throws {
    let data = Data(#"{"schema_version":"glassbox-passive-evidence/v1","observations":3,"relations":0,"bundle_bytes":128,"bundle_sha256":"abc","published_to_inherited_descriptor":true}"#.utf8)
    let receipt = try JSONDecoder().decode(PassiveEvidenceReceipt.self, from: data)
    XCTAssertEqual(receipt.schemaVersion, "glassbox-passive-evidence/v1")
    XCTAssertTrue(receipt.publishedToInheritedDescriptor)
    XCTAssertEqual(receipt.relations, 0)
  }
}
