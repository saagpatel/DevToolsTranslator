import Foundation

enum PassivePhase: Equatable {
  case idle
  case choosingDestination
  case capturing
  case cancelling
  case completed
  case failed(String)

  var label: String {
    switch self {
    case .idle: "Ready"
    case .choosingDestination: "Choosing evidence destination"
    case .capturing: "Reading ordinary neighbor-table context"
    case .cancelling: "Cancelling capture"
    case .completed: "Evidence bundle ready"
    case .failed: "Capture failed"
    }
  }
}

struct PassiveBrokerMessage: Decodable {
  let type: String
  let evidence: PassiveEvidenceReceipt?
  let code: String?
}

struct PassiveEvidenceReceipt: Decodable, Equatable {
  let schemaVersion: String
  let observations: Int
  let relations: Int
  let bundleBytes: Int
  let bundleSHA256: String
  let publishedToInheritedDescriptor: Bool

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case observations, relations
    case bundleBytes = "bundle_bytes"
    case bundleSHA256 = "bundle_sha256"
    case publishedToInheritedDescriptor = "published_to_inherited_descriptor"
  }
}

enum PassiveCaptureInput {
  case liveSnapshot
  case fixture(Data)
}
