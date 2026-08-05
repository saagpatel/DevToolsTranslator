import Darwin
import Foundation

enum BoundedProcessError: Error, Equatable {
  case launchFailed
  case timedOut
}

struct BoundedProcessResult: Equatable, Sendable {
  let status: Int32
}

enum BoundedProcess {
  static func run(
    executable: URL,
    arguments: [String],
    environment: [String: String] = [:],
    timeout: Duration
  ) throws -> BoundedProcessResult {
    let process = Process()
    process.executableURL = executable
    process.arguments = arguments
    process.environment = environment
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    let completed = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in completed.signal() }
    do {
      try process.run()
    } catch {
      throw BoundedProcessError.launchFailed
    }
    let components = timeout.components
    let seconds = max(0, components.seconds)
    let nanoseconds = max(0, components.attoseconds / 1_000_000_000)
    let deadline = DispatchTime.now() + .seconds(Int(seconds)) + .nanoseconds(Int(nanoseconds))
    if completed.wait(timeout: deadline) == .timedOut {
      process.terminate()
      if completed.wait(timeout: .now() + .seconds(1)) == .timedOut {
        kill(process.processIdentifier, SIGKILL)
        _ = completed.wait(timeout: .now() + .seconds(1))
      }
      throw BoundedProcessError.timedOut
    }
    return BoundedProcessResult(status: process.terminationStatus)
  }
}

enum InstrumentsTraceAdapterError: Error, Equatable {
  case unavailable
  case invalidStagingPath
  case conversionFailed
  case outputInvalid
}

struct InstrumentsTraceAdapter: Sendable {
  static let conversionTimeout: Duration = .seconds(1_800)
  static let maximumHARBytes: Int = 4 * 1024 * 1024 * 1024
  let xctraceURL: URL

  static func discover() -> InstrumentsTraceAdapter? {
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
    process.arguments = ["--find", "xctrace"]
    process.environment = ["PATH": "/usr/bin:/bin"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    guard (try? process.run()) != nil else { return nil }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    guard data.count <= 4_096,
      let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
      path.hasSuffix("/Contents/Developer/usr/bin/xctrace"),
      FileManager.default.isExecutableFile(atPath: path)
    else { return nil }
    return InstrumentsTraceAdapter(xctraceURL: URL(fileURLWithPath: path))
  }

  func exportNetworkHAR(
    stagedTrace: URL,
    outputHAR: URL,
    stagingRoot: URL
  ) throws {
    guard isDirectChild(stagedTrace, of: stagingRoot, extension: "trace"),
      isDirectChild(outputHAR, of: stagingRoot, extension: "har")
    else { throw InstrumentsTraceAdapterError.invalidStagingPath }
    let result = try BoundedProcess.run(
      executable: xctraceURL,
      arguments: [
        "export", "--quiet", "--input", stagedTrace.path, "--har", "--output", outputHAR.path,
      ],
      environment: ["PATH": "/usr/bin:/bin"],
      timeout: Self.conversionTimeout)
    guard result.status == 0 else { throw InstrumentsTraceAdapterError.conversionFailed }
    let values = try outputHAR.resourceValues(forKeys: [
      .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey,
    ])
    guard values.isRegularFile == true, values.isSymbolicLink != true,
      let size = values.fileSize, size > 0, size <= Self.maximumHARBytes
    else { throw InstrumentsTraceAdapterError.outputInvalid }
  }

  private func isDirectChild(_ url: URL, of root: URL, extension expected: String) -> Bool {
    let standardized = url.standardizedFileURL
    let standardizedRoot = root.standardizedFileURL
    return standardized.deletingLastPathComponent() == standardizedRoot
      && standardized.pathExtension == expected
      && UUID(uuidString: standardized.deletingPathExtension().lastPathComponent) != nil
  }
}

enum InstrumentsTraceProjectionCommand {
  static func run() -> Int32 {
    var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    guard fcntl(STDIN_FILENO, F_GETPATH, &path) == 0 else {
      writeError("instruments-projector: selected trace handle unavailable\n")
      return 2
    }
    let decodedPath = String(
      decoding: path.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    let source = URL(fileURLWithPath: decodedPath, isDirectory: true)
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("glassbox-instruments-\(UUID().uuidString.lowercased())", isDirectory: true)
    do {
      try FileManager.default.createDirectory(
        at: root, withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: root) }
      let staged = try SelectedArtifactStager.stageTrace(source: source, into: root)
      guard let adapter = InstrumentsTraceAdapter.discover() else {
        writeError("instruments-projector: compatible Xcode unavailable\n")
        return 3
      }
      let output = root.appendingPathComponent(UUID().uuidString.lowercased())
        .appendingPathExtension("har")
      try adapter.exportNetworkHAR(stagedTrace: staged, outputHAR: output, stagingRoot: root)
      let values = try output.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
      guard values.isRegularFile == true, let size = values.fileSize, size > 0,
        size <= InstrumentsTraceAdapter.maximumHARBytes
      else { throw InstrumentsTraceAdapterError.outputInvalid }
      let handle = try FileHandle(forReadingFrom: output)
      defer { try? handle.close() }
      while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
        try FileHandle.standardOutput.write(contentsOf: chunk)
      }
      return 0
    } catch {
      writeError("instruments-projector: trace rejected\n")
      return 2
    }
  }

  private static func writeError(_ message: String) {
    try? FileHandle.standardError.write(contentsOf: Data(message.utf8))
  }
}
