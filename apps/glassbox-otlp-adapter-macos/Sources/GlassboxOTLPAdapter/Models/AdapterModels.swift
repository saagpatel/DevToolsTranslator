import Foundation

enum AdapterPhase: Equatable {
  case idle
  case choosingDestination
  case starting
  case listening
  case stopping
  case completed
  case failed(String)

  var label: String {
    switch self {
    case .idle: "Ready"
    case .choosingDestination: "Choosing evidence destination"
    case .starting: "Starting isolated receiver"
    case .listening: "Capturing"
    case .stopping: "Stopping and validating evidence"
    case .completed: "Evidence bundle ready"
    case .failed: "Capture failed"
    }
  }
}

struct BrokerConfiguration: Encodable, Equatable {
  let protocolVersion = 1
  let bind = "127.0.0.1:0"
  let sessionID: String
  let sourceID: String
  let sourceEpoch: UInt64 = 1
  let credential: String
  let maxFrameBytes = 1_048_576
  let maxEvents = 100_000
  let maxTotalBytes = 268_435_456
  let maxEventsPerSecond = 20_000
  let watchdogTimeoutMS = 30_000

  enum CodingKeys: String, CodingKey {
    case protocolVersion = "protocol_version"
    case bind
    case sessionID = "session_id"
    case sourceID = "source_id"
    case sourceEpoch = "source_epoch"
    case credential
    case maxFrameBytes = "max_frame_bytes"
    case maxEvents = "max_events"
    case maxTotalBytes = "max_total_bytes"
    case maxEventsPerSecond = "max_events_per_second"
    case watchdogTimeoutMS = "watchdog_timeout_ms"
  }
}

struct BrokerMessage: Decodable {
  let type: String
  let bound: String?
  let acceptedEvents: UInt64?
  let evidence: EvidenceReceipt?
  let code: String?

  enum CodingKeys: String, CodingKey {
    case type, bound, evidence, code
    case acceptedEvents = "accepted_events"
  }
}

struct EvidenceReceipt: Decodable, Equatable {
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
