import Darwin
import Foundation
import Testing

@testable import GlassboxInstrumentsAdapter

@Test func conversionUsesDirectoryOutputAndStreamsOneHAR() throws {
  let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let source = base.appendingPathComponent("selected.trace", isDirectory: true)
  let output = base.appendingPathComponent("output.har")
  let tool = base.appendingPathComponent("fake-xctrace")
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: base) }
  try Data("trace".utf8).write(to: source.appendingPathComponent("data"))
  try Data().write(to: output)
  #expect(
    try InstrumentsTraceStager.sha256(directory: source)
      == "6414919fca2dee2ce1595d4e065e4edac01d30907b284d2fc081b39803752462")
  let script = """
    #!/bin/sh
    output=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--output" ]; then
        shift
        output="$1"
      fi
      shift
    done
    test -n "$output"
    printf '%s' '{"log":{"version":"1.2","entries":[{}]}}' > "$output/fixture.har"
    """
  try Data(script.utf8).write(to: tool)
  #expect(chmod(tool.path, 0o700) == 0)
  let sourceDescriptor = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
  #expect(sourceDescriptor >= 0)
  guard sourceDescriptor >= 0 else { return }
  defer { close(sourceDescriptor) }
  let outputHandle = try FileHandle(forWritingTo: output)
  defer { try? outputHandle.close() }

  try InstrumentsConversionService.convert(
    sourceDescriptor: sourceDescriptor,
    to: outputHandle,
    xctraceURL: tool,
    expectedSourceHash: try InstrumentsTraceStager.sha256(directory: source))
  try outputHandle.synchronize()
  #expect(
    try Data(contentsOf: output)
      == Data("{\"log\":{\"version\":\"1.2\",\"entries\":[{}]}}".utf8))
}

@Test func conversionIsDescriptorRelativeAndRejectsWrongReviewedHash() throws {
  let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let source = base.appendingPathComponent("selected.trace", isDirectory: true)
  let renamed = base.appendingPathComponent("renamed.trace", isDirectory: true)
  let output = base.appendingPathComponent("output.har")
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: base) }
  try Data("trace".utf8).write(to: source.appendingPathComponent("data"))
  try Data().write(to: output)
  let expectedHash = try InstrumentsTraceStager.sha256(directory: source)
  let sourceDescriptor = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
  #expect(sourceDescriptor >= 0)
  guard sourceDescriptor >= 0 else { return }
  defer { close(sourceDescriptor) }
  try FileManager.default.moveItem(at: source, to: renamed)
  let outputHandle = try FileHandle(forWritingTo: output)
  defer { try? outputHandle.close() }

  #expect(throws: InstrumentsConversionError.conversionFailed) {
    try InstrumentsConversionService.convert(
      sourceDescriptor: sourceDescriptor,
      to: outputHandle,
      xctraceURL: URL(fileURLWithPath: "/usr/bin/false"),
      expectedSourceHash: expectedHash)
  }
  #expect(throws: InstrumentsConversionError.sourceHashMismatch) {
    try InstrumentsConversionService.convert(
      sourceDescriptor: sourceDescriptor,
      to: outputHandle,
      xctraceURL: URL(fileURLWithPath: "/usr/bin/false"),
      expectedSourceHash: String(repeating: "0", count: 64))
  }
}

@Test func conversionRejectsTraceContainingSymlink() throws {
  let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let source = base.appendingPathComponent("selected.trace", isDirectory: true)
  let output = base.appendingPathComponent("output.har")
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: base) }
  let target = source.appendingPathComponent("target")
  try Data("trace".utf8).write(to: target)
  try FileManager.default.createSymbolicLink(
    at: source.appendingPathComponent("link"),
    withDestinationURL: target)
  try Data().write(to: output)
  let sourceDescriptor = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
  #expect(sourceDescriptor >= 0)
  guard sourceDescriptor >= 0 else { return }
  defer { close(sourceDescriptor) }
  let outputHandle = try FileHandle(forWritingTo: output)
  defer { try? outputHandle.close() }

  #expect(throws: InstrumentsConversionError.sourceRejected) {
    try InstrumentsConversionService.convert(
      sourceDescriptor: sourceDescriptor,
      to: outputHandle,
      xctraceURL: URL(fileURLWithPath: "/usr/bin/false"))
  }
}
