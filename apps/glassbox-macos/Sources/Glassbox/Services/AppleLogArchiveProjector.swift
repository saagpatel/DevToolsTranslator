import CryptoKit
import Darwin
import Foundation
import OSLog

enum AppleLogProjectionError: Error, Equatable {
  case invalidSourceHash
  case invalidTimestamp
  case invalidProcessIdentifier
  case tooManyEntries
}

struct AppleLogMetadata: Equatable, Sendable {
  enum EntryKind: String, Sendable { case log, signpost, activity, loss, unknown }
  enum Level: String, Sendable { case undefined, debug, info, notice, error, fault }
  enum SignpostType: String, Sendable { case begin, end, event }

  let timestampUnixNanoseconds: String
  let entryKind: EntryKind
  let level: Level
  let processID: UInt32
  let threadID: UInt64
  let activityID: UInt64
  let signpostID: UInt64?
  let signpostType: SignpostType?
}

enum AppleLogProjectionWriter {
  static let schemaVersion = "glassbox-apple-log-projection/v1"
  static let maximumEntries = 1_000_000

  static func write<S: Sequence>(
    entries: S,
    sourceArtifactSHA256: String,
    to output: FileHandle
  ) throws where S.Element == AppleLogMetadata {
    var stream = try AppleLogProjectionStream(
      sourceArtifactSHA256: sourceArtifactSHA256, output: output)
    for entry in entries {
      try stream.append(entry)
    }
    try stream.finish()
  }

  fileprivate static func writeHashed(
    _ object: [String: Any],
    to output: FileHandle,
    digest: inout SHA256
  ) throws {
    let line = try encodedLine(object)
    digest.update(data: line)
    try output.write(contentsOf: line)
  }

  fileprivate static func writeLine(_ object: [String: Any], to output: FileHandle) throws {
    try output.write(contentsOf: encodedLine(object))
  }

  fileprivate static func encodedLine(_ object: [String: Any]) throws -> Data {
    var data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    data.append(0x0A)
    return data
  }

  fileprivate static func isLowercaseSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.utf8.allSatisfy { byte in
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66)
      }
  }
}

private struct AppleLogProjectionStream {
  let output: FileHandle
  var digest = SHA256()
  var count = 0

  init(sourceArtifactSHA256: String, output: FileHandle) throws {
    guard AppleLogProjectionWriter.isLowercaseSHA256(sourceArtifactSHA256) else {
      throw AppleLogProjectionError.invalidSourceHash
    }
    self.output = output
    try AppleLogProjectionWriter.writeHashed(
      [
        "type": "header",
        "schema_version": AppleLogProjectionWriter.schemaVersion,
        "source_artifact_sha256": sourceArtifactSHA256,
      ], to: output, digest: &digest)
  }

  mutating func append(_ entry: AppleLogMetadata) throws {
    count += 1
    guard count <= AppleLogProjectionWriter.maximumEntries else {
      throw AppleLogProjectionError.tooManyEntries
    }
    var object: [String: Any] = [
      "type": "entry",
      "ordinal": count,
      "timestamp_unix_ns": entry.timestampUnixNanoseconds,
      "entry_kind": entry.entryKind.rawValue,
      "level": entry.level.rawValue,
      "process_id": entry.processID,
      "thread_id": entry.threadID,
      "activity_id": entry.activityID,
    ]
    if let signpostID = entry.signpostID { object["signpost_id"] = signpostID }
    if let signpostType = entry.signpostType { object["signpost_type"] = signpostType.rawValue }
    try AppleLogProjectionWriter.writeHashed(object, to: output, digest: &digest)
  }

  mutating func finish() throws {
    let streamSHA256 = digest.finalize().map { String(format: "%02x", $0) }.joined()
    try AppleLogProjectionWriter.writeLine(
      ["type": "end", "records": count, "stream_sha256": streamSHA256], to: output)
  }
}

enum AppleLogArchiveProjector {
  static func project(
    archiveURL: URL,
    sourceArtifactSHA256: String,
    to output: FileHandle
  ) throws {
    let store = try OSLogStore(url: archiveURL)
    var stream = try AppleLogProjectionStream(
      sourceArtifactSHA256: sourceArtifactSHA256, output: output)
    for entry in try store.getEntries() {
      try stream.append(projectMetadata(entry))
    }
    try stream.finish()
  }

  private static func projectMetadata(_ entry: OSLogEntry) throws -> AppleLogMetadata {
    let scaled = entry.date.timeIntervalSince1970 * 1_000_000_000
    guard scaled.isFinite, scaled >= Double(Int64.min), scaled <= Double(Int64.max) else {
      throw AppleLogProjectionError.invalidTimestamp
    }
    let processEntry = entry as? any OSLogEntryFromProcess
    let processIdentifier = processEntry?.processIdentifier ?? 0
    guard processIdentifier >= 0 else {
      throw AppleLogProjectionError.invalidProcessIdentifier
    }
    let kind: AppleLogMetadata.EntryKind
    if entry is OSLogEntrySignpost {
      kind = .signpost
    } else if entry is OSLogEntryLog {
      kind = .log
    } else if entry is OSLogEntryActivity {
      kind = .activity
    } else {
      kind = .unknown
    }
    let logLevel: AppleLogMetadata.Level
    if let log = entry as? OSLogEntryLog {
      switch log.level {
      case .undefined: logLevel = .undefined
      case .debug: logLevel = .debug
      case .info: logLevel = .info
      case .notice: logLevel = .notice
      case .error: logLevel = .error
      case .fault: logLevel = .fault
      @unknown default: logLevel = .undefined
      }
    } else {
      logLevel = .undefined
    }
    var signpostID: UInt64?
    var signpostType: AppleLogMetadata.SignpostType?
    if let signpost = entry as? OSLogEntrySignpost {
      signpostID = signpost.signpostIdentifier
      switch signpost.signpostType {
      case .intervalBegin: signpostType = .begin
      case .intervalEnd: signpostType = .end
      case .event: signpostType = .event
      case .undefined: signpostType = nil
      @unknown default: signpostType = nil
      }
    }
    return AppleLogMetadata(
      timestampUnixNanoseconds: String(Int64(scaled.rounded())),
      entryKind: kind,
      level: logLevel,
      processID: UInt32(processIdentifier),
      threadID: processEntry?.threadIdentifier ?? 0,
      activityID: processEntry?.activityIdentifier ?? 0,
      signpostID: signpostID,
      signpostType: signpostType)
  }
}

enum AppleLogProjectionCommand {
  static func run() -> Int32 {
    guard
      let sourceHash = ProcessInfo.processInfo.environment["GLASSBOX_SOURCE_ARTIFACT_SHA256"],
      AppleLogProjectionWriter.isLowercaseSHA256(sourceHash)
    else {
      writeError("apple-log-projector: invalid source identity\n")
      return 2
    }
    var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    guard fcntl(STDIN_FILENO, F_GETPATH, &path) == 0 else {
      writeError("apple-log-projector: selected archive handle unavailable\n")
      return 2
    }
    let decodedPath = String(
      decoding: path.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    let archiveURL = URL(fileURLWithPath: decodedPath, isDirectory: true)
    do {
      let values = try archiveURL.resourceValues(forKeys: [
        .isDirectoryKey, .isSymbolicLinkKey,
      ])
      guard archiveURL.pathExtension == "logarchive", values.isDirectory == true,
        values.isSymbolicLink != true
      else {
        writeError("apple-log-projector: selected object is not a log archive directory\n")
        return 2
      }
      try AppleLogArchiveProjector.project(
        archiveURL: archiveURL,
        sourceArtifactSHA256: sourceHash,
        to: .standardOutput)
      return 0
    } catch {
      writeError("apple-log-projector: archive rejected\n")
      return 2
    }
  }

  private static func writeError(_ message: String) {
    try? FileHandle.standardError.write(contentsOf: Data(message.utf8))
  }
}
