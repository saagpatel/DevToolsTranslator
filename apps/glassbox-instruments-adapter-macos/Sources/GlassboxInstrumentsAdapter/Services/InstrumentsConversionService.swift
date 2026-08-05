import Darwin
import Foundation

enum InstrumentsConversionError: Error, Equatable {
  case invalidSource
  case sourceRejected
  case sourceChanged
  case sourceHashMismatch
  case tooManyEntries
  case sourceTooLarge
  case xcodeUnavailable
  case conversionFailed
  case outputInvalid
  case timedOut
}

enum InstrumentsConversionService {
  static let maximumHARBytes: UInt64 = 4 * 1024 * 1024 * 1024

  static func convert(
    sourceDescriptor: Int32,
    to output: FileHandle,
    xctraceURL: URL? = nil,
    expectedSourceHash: String? = nil
  ) throws {
    let temporaryRoot = FileManager.default.temporaryDirectory
      .appendingPathComponent("glassbox-instruments-adapter-\(UUID().uuidString.lowercased())")
    try FileManager.default.createDirectory(
      at: temporaryRoot,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: temporaryRoot) }

    let stagedTrace = try InstrumentsTraceStager.stage(
      sourceDescriptor: sourceDescriptor, into: temporaryRoot)
    if let expectedSourceHash {
      let stagedHash = try InstrumentsTraceStager.sha256(directory: stagedTrace)
      guard isLowercaseSHA256(expectedSourceHash), stagedHash == expectedSourceHash
      else { throw InstrumentsConversionError.sourceHashMismatch }
    }
    let xctrace = try xctraceURL ?? discoverXCTrace()
    let exportDirectory = temporaryRoot.appendingPathComponent(
      UUID().uuidString.lowercased(), isDirectory: true)
    try FileManager.default.createDirectory(
      at: exportDirectory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    let result = try runBounded(
      executable: xctrace,
      arguments: [
        "export", "--quiet", "--input", stagedTrace.path, "--har", "--output",
        exportDirectory.path,
      ],
      timeoutSeconds: 1_800)
    guard result == 0 else { throw InstrumentsConversionError.conversionFailed }

    let outputs = try FileManager.default.contentsOfDirectory(
      at: exportDirectory,
      includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey],
      options: [.skipsHiddenFiles])
    guard outputs.count == 1, let har = outputs.first, har.pathExtension == "har" else {
      throw InstrumentsConversionError.outputInvalid
    }
    let values = try har.resourceValues(forKeys: [
      .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey,
    ])
    guard values.isRegularFile == true, values.isSymbolicLink != true,
      let size = values.fileSize, size > 0, UInt64(size) <= maximumHARBytes
    else { throw InstrumentsConversionError.outputInvalid }
    let input = try FileHandle(forReadingFrom: har)
    defer { try? input.close() }
    var copied: UInt64 = 0
    while let chunk = try input.read(upToCount: 1024 * 1024), !chunk.isEmpty {
      copied += UInt64(chunk.count)
      guard copied <= UInt64(size) else { throw InstrumentsConversionError.outputInvalid }
      try output.write(contentsOf: chunk)
    }
    guard copied == UInt64(size) else { throw InstrumentsConversionError.outputInvalid }
  }

  private static func discoverXCTrace() throws -> URL {
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    process.arguments = ["--find", "xctrace"]
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { throw InstrumentsConversionError.xcodeUnavailable }
    process.waitUntilExit()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0, data.count <= 4_096,
      let path = String(data: data, encoding: .utf8)?.trimmingCharacters(
        in: .whitespacesAndNewlines),
      path.hasSuffix("/Contents/Developer/usr/bin/xctrace"),
      FileManager.default.isExecutableFile(atPath: path)
    else { throw InstrumentsConversionError.xcodeUnavailable }
    return URL(fileURLWithPath: path)
  }

  private static func runBounded(
    executable: URL,
    arguments: [String],
    timeoutSeconds: Int
  ) throws -> Int32 {
    let process = Process()
    process.executableURL = executable
    process.arguments = arguments
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    let completed = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in completed.signal() }
    do { try process.run() } catch { throw InstrumentsConversionError.conversionFailed }
    guard completed.wait(timeout: .now() + .seconds(timeoutSeconds)) == .success else {
      process.terminate()
      if completed.wait(timeout: .now() + .seconds(1)) != .success {
        kill(process.processIdentifier, SIGKILL)
        _ = completed.wait(timeout: .now() + .seconds(1))
      }
      throw InstrumentsConversionError.timedOut
    }
    return process.terminationStatus
  }

  private static func isLowercaseSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.utf8.allSatisfy { byte in
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x61 && byte <= 0x66)
      }
  }
}

enum InstrumentsProjectionCommand {
  static func run() -> Int32 {
    guard
      let sourceHash = ProcessInfo.processInfo.environment["GLASSBOX_SOURCE_ARTIFACT_SHA256"]
    else {
      writeError("instruments-adapter: invalid source identity\n")
      return 2
    }
    do {
      try InstrumentsConversionService.convert(
        sourceDescriptor: STDIN_FILENO,
        to: .standardOutput,
        expectedSourceHash: sourceHash)
      return 0
    } catch InstrumentsConversionError.xcodeUnavailable {
      writeError("instruments-adapter: compatible Xcode unavailable\n")
      return 3
    } catch {
      writeError("instruments-adapter: trace rejected\n")
      return 2
    }
  }

  private static func writeError(_ message: String) {
    try? FileHandle.standardError.write(contentsOf: Data(message.utf8))
  }
}
