import Foundation
import Darwin

enum EvidenceImportFormat: String, CaseIterable, Sendable {
  case har
  case otlpJSONL = "otlp-jsonl"
  case pcap
  case pcapng
  case glassbox

  static func resolve(_ url: URL) -> EvidenceImportFormat? {
    switch url.pathExtension.lowercased() {
    case "har": .har
    case "jsonl", "ndjson": .otlpJSONL
    case "pcap": .pcap
    case "pcapng": .pcapng
    case "glassbox": .glassbox
    default: nil
    }
  }
}

struct RustEvidenceService: Sendable {
  static let maximumImportBytes: UInt64 = 4 * 1024 * 1024 * 1024
  static let maximumPayloadBytes = 8 * 1024 * 1024
  let helperURL: URL

  init(bundle: Bundle = .main) throws {
    let candidate = bundle.bundleURL
      .appendingPathComponent("Contents", isDirectory: true)
      .appendingPathComponent("Helpers", isDirectory: true)
      .appendingPathComponent("glassbox-native-bridge", isDirectory: false)
    guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
      throw NativeShellError.helperUnavailable
    }
    helperURL = candidate
  }

  init(helperURL: URL) {
    self.helperURL = helperURL
  }

  func load() throws -> NativeShellPayload {
    try run(arguments: [], standardInput: nil, timeout: .seconds(10))
  }

  func loadImport(
    selected: SelectedArtifactHasher.HashedRegularFile,
    format: EvidenceImportFormat,
    captureSession: UUID
  ) throws -> NativeShellPayload {
    try run(
      arguments: [
        "--import", format.rawValue, selected.sha256,
        captureSession.uuidString.lowercased().replacingOccurrences(of: "-", with: "_"),
      ],
      standardInput: selected.handle,
      timeout: .seconds(120))
  }

  func loadResourceSample(
    stopInput: FileHandle,
    captureSession: UUID,
    intervalMilliseconds: UInt64 = 500,
    maximumSamples: Int = 60
  ) throws -> NativeShellPayload {
    try run(
      arguments: [
        "--sample-system",
        captureSession.uuidString.lowercased().replacingOccurrences(of: "-", with: "_"),
        String(intervalMilliseconds), String(maximumSamples),
      ],
      standardInput: stopInput,
      timeout: .seconds(40))
  }

  private func run(
    arguments: [String], standardInput: FileHandle?, timeout: Duration
  ) throws -> NativeShellPayload {
    let temporary = FileManager.default.temporaryDirectory
      .appendingPathComponent("glassbox-helper-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
      at: temporary, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: temporary) }
    let outputURL = temporary.appendingPathComponent("output")
    let errorURL = temporary.appendingPathComponent("error")
    guard
      FileManager.default.createFile(
        atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600]),
      FileManager.default.createFile(
        atPath: errorURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
    else { throw NativeShellError.helperFailed("temporary output unavailable") }
    let outputHandle = try FileHandle(forWritingTo: outputURL)
    let errorHandle = try FileHandle(forWritingTo: errorURL)
    defer {
      try? outputHandle.close()
      try? errorHandle.close()
    }
    let process = Process()
    process.executableURL = helperURL
    process.arguments = arguments
    process.environment = [:]
    process.standardInput = standardInput ?? FileHandle.nullDevice
    process.standardOutput = outputHandle
    process.standardError = errorHandle
    let completed = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in completed.signal() }
    do {
      try process.run()
    } catch {
      throw NativeShellError.helperFailed("launch failed")
    }
    let components = timeout.components
    let deadline = DispatchTime.now() + .seconds(Int(max(0, components.seconds)))
      + .nanoseconds(Int(max(0, components.attoseconds / 1_000_000_000)))
    if completed.wait(timeout: deadline) == .timedOut {
      process.terminate()
      if completed.wait(timeout: .now() + .seconds(1)) == .timedOut {
        kill(process.processIdentifier, SIGKILL)
        _ = completed.wait(timeout: .now() + .seconds(1))
      }
      throw NativeShellError.helperTimedOut
    }
    try outputHandle.synchronize()
    try errorHandle.synchronize()
    let outputSize = try FileManager.default.attributesOfItem(atPath: outputURL.path)[.size]
      as? NSNumber
    let errorSize = try FileManager.default.attributesOfItem(atPath: errorURL.path)[.size]
      as? NSNumber
    guard outputSize?.intValue ?? Int.max <= Self.maximumPayloadBytes,
      errorSize?.intValue ?? Int.max <= 4_096
    else { throw NativeShellError.helperOutputTooLarge }
    let output = try Data(contentsOf: outputURL, options: [.mappedIfSafe])
    let errorOutput = try Data(contentsOf: errorURL, options: [.mappedIfSafe])
    guard process.terminationStatus == 0 else {
      let message = String(data: errorOutput, encoding: .utf8)?.trimmingCharacters(
        in: .whitespacesAndNewlines)
      throw NativeShellError.helperFailed(
        message?.isEmpty == false ? message! : "exit \(process.terminationStatus)")
    }
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    guard let payload = try? decoder.decode(NativeShellPayload.self, from: output) else {
      throw NativeShellError.invalidOutput
    }
    return try payload.validated()
  }
}
