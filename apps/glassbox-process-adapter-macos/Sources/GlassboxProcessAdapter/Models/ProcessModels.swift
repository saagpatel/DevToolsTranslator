import AppKit
import Foundation

struct ProcessCandidate: Identifiable, Equatable, Sendable {
  let processIdentifier: Int32
  let bundleIdentifier: String
  let displayName: String

  var id: String { "\(bundleIdentifier):\(processIdentifier)" }

  @MainActor
  static func current() -> [ProcessCandidate] {
    NSWorkspace.shared.runningApplications
      .filter {
        !$0.isTerminated && $0.activationPolicy == .regular && $0.processIdentifier > 0
          && validBundleIdentifier($0.bundleIdentifier)
      }
      .compactMap { application in
        guard let bundleIdentifier = application.bundleIdentifier else { return nil }
        return ProcessCandidate(
          processIdentifier: application.processIdentifier,
          bundleIdentifier: bundleIdentifier,
          displayName: application.localizedName ?? bundleIdentifier)
      }
      .sorted {
        let order = $0.displayName.localizedCaseInsensitiveCompare($1.displayName)
        return order == .orderedSame
          ? $0.processIdentifier < $1.processIdentifier : order == .orderedAscending
      }
  }

  @MainActor
  var isStillSelectedApplication: Bool {
    guard let application = NSRunningApplication(processIdentifier: processIdentifier) else {
      return false
    }
    return !application.isTerminated && application.bundleIdentifier == bundleIdentifier
  }

  private static func validBundleIdentifier(_ value: String?) -> Bool {
    guard let value, (3...255).contains(value.utf8.count), value.contains(".") else {
      return false
    }
    return value.utf8.allSatisfy { byte in
      (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte)
        || byte == 45 || byte == 46
    }
  }
}

enum ProcessAdapterPhase: Equatable {
  case ready
  case choosingDestination
  case capturing
  case stopping
  case cancelling
  case completed
  case failed(String)

  var label: String {
    switch self {
    case .ready: "Ready"
    case .choosingDestination: "Choosing evidence destination"
    case .capturing: "Sampling selected application"
    case .stopping: "Stopping and validating evidence"
    case .cancelling: "Cancelling and discarding"
    case .completed: "Evidence bundle ready"
    case .failed: "Capture failed"
    }
  }
}

struct ProcessBrokerMessage: Decodable {
  let type: String
  let evidence: ProcessEvidenceReceipt?
  let code: String?
}

struct ProcessEvidenceReceipt: Decodable, Equatable {
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
