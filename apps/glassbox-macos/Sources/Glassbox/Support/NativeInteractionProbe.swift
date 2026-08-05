import AppKit
import Foundation

struct NativeInteractionProbeResult: Codable {
  let schemaVersion = "glassbox-native-interaction-sample/v1"
  var samples: [[NativeInteractionProbeValue]] = []
  var errors: [String] = []

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case samples, errors
  }

  func base64URL() -> String {
    let data = (try? JSONEncoder().encode(self)) ?? Data()
    return data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}

enum NativeInteractionProbeValue: Codable {
  case code(String)
  case duration(Double)

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if let value = try? container.decode(String.self) {
      self = .code(value)
    } else {
      self = .duration(try container.decode(Double.self))
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .code(let value): try container.encode(value)
    case .duration(let value): try container.encode(value)
    }
  }
}

@MainActor
enum NativeInteractionProbe {
  static func run(store: InvestigationStore) async -> NativeInteractionProbeResult {
    var result = NativeInteractionProbeResult()
    try? await Task.sleep(for: .milliseconds(500))
    for round in 0..<30 {
      guard await measure(code: "t", result: &result, store: store, action: { store.mode = .table })
      else { return result }
      if store.mode != .table { result.errors.append("table view did not render") }
      try? await Task.sleep(for: .milliseconds(50))

      guard let rows = store.payload?.view.evidenceTable, !rows.isEmpty else {
        result.errors.append("evidence table became empty")
        return result
      }
      let selected = rows[(round + 1) % rows.count].id
      guard
        await measure(
          code: "s", result: &result, store: store, action: { store.selectedID = selected })
      else { return result }
      if store.selectedID != selected { result.errors.append("evidence selection did not render") }
      try? await Task.sleep(for: .milliseconds(50))

      guard
        await measure(
          code: "o", result: &result, store: store, action: { store.exportPresented = true })
      else { return result }
      if !store.exportPresented { result.errors.append("export review did not open") }
      try? await Task.sleep(for: .milliseconds(400))

      guard
        await measure(
          code: "c", result: &result, store: store, action: { store.exportPresented = false })
      else { return result }
      if store.exportPresented { result.errors.append("export review did not close") }
      try? await Task.sleep(for: .milliseconds(400))

      guard
        await measure(
          code: "l", result: &result, store: store, action: { store.mode = .timeline })
      else { return result }
      if store.mode != .timeline { result.errors.append("timeline view did not render") }
      try? await Task.sleep(for: .milliseconds(50))
    }
    return result
  }

  private static func measure(
    code: String,
    result: inout NativeInteractionProbeResult,
    store: InvestigationStore,
    action: () -> Void
  ) async -> Bool {
    guard let milliseconds = await store.measureProbeRender(code: code, action: action) else {
      result.errors.append("\(code) view did not acknowledge render within 2 seconds")
      return false
    }
    result.samples.append([.code(code), .duration(milliseconds)])
    return true
  }
}
