import Foundation
import XCTest
@testable import GlassboxProcessAdapter

final class ProcessModelsTests: XCTestCase {
  func testReceiptRequiresExplicitInheritedDescriptorPublication() throws {
    let data = Data(#"{"schema_version":"glassbox-process-evidence/v1","observations":3,"relations":0,"bundle_bytes":128,"bundle_sha256":"abc","published_to_inherited_descriptor":true}"#.utf8)
    let receipt = try JSONDecoder().decode(ProcessEvidenceReceipt.self, from: data)
    XCTAssertEqual(receipt.schemaVersion, "glassbox-process-evidence/v1")
    XCTAssertEqual(receipt.relations, 0)
    XCTAssertTrue(receipt.publishedToInheritedDescriptor)
  }
}
