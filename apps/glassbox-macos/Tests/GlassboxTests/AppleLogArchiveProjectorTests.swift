import Foundation
import Testing
@testable import Glassbox

@Test func appleLogProjectionIsTerminalBoundAndMetadataOnly() throws {
  let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  FileManager.default.createFile(atPath: temporary.path, contents: nil)
  defer { try? FileManager.default.removeItem(at: temporary) }
  let handle = try FileHandle(forWritingTo: temporary)
  defer { try? handle.close() }
  let entries = [
    AppleLogMetadata(
      timestampUnixNanoseconds: "1720000000000000000",
      entryKind: .log,
      level: .info,
      processID: 42,
      threadID: 7,
      activityID: 9,
      signpostID: nil,
      signpostType: nil),
    AppleLogMetadata(
      timestampUnixNanoseconds: "1720000000001000000",
      entryKind: .signpost,
      level: .notice,
      processID: 42,
      threadID: 8,
      activityID: 9,
      signpostID: 11,
      signpostType: .begin),
  ]
  try AppleLogProjectionWriter.write(
    entries: entries,
    sourceArtifactSHA256: String(repeating: "a", count: 64),
    to: handle)
  try handle.synchronize()
  let output = try String(contentsOf: temporary, encoding: .utf8)
  let lines = output.split(separator: "\n")
  #expect(lines.count == 4)
  #expect(lines.last?.contains("\"type\":\"end\"") == true)
  for forbidden in ["message", "subsystem", "category", "process_name", "sender", "path"] {
    #expect(!output.contains(forbidden))
  }
}

@Test func appleLogProjectionRejectsInvalidSourceHash() throws {
  let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  FileManager.default.createFile(atPath: temporary.path, contents: nil)
  defer { try? FileManager.default.removeItem(at: temporary) }
  let handle = try FileHandle(forWritingTo: temporary)
  defer { try? handle.close() }
  #expect(throws: AppleLogProjectionError.invalidSourceHash) {
    try AppleLogProjectionWriter.write(entries: [], sourceArtifactSHA256: "not-a-hash", to: handle)
  }
}
