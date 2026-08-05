import Darwin
import Foundation

final class ProcessBrokerProcess: @unchecked Sendable {
  typealias MessageHandler = @Sendable (ProcessBrokerMessage) -> Void
  typealias ExitHandler = @Sendable (Int32, String) -> Void

  private let lock = NSLock()
  private var processID: pid_t?
  private var inputHandle: FileHandle?
  private var consentHandle: FileHandle?
  private var outputHandle: FileHandle?
  private var errorHandle: FileHandle?
  private var outputBuffer = Data()
  private var errorBuffer = Data()

  func start(
    helperURL: URL,
    evidenceURL: URL,
    candidate: ProcessCandidate,
    captureSession: String,
    consentCapability: String,
    intervalMilliseconds: UInt64 = 500,
    maximumSamples: Int = 60,
    onMessage: @escaping MessageHandler,
    onExit: @escaping ExitHandler
  ) throws {
    lock.lock()
    defer { lock.unlock() }
    guard processID == nil else { throw ProcessBrokerError.alreadyRunning }
    let evidenceDescriptor = open(evidenceURL.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
    guard evidenceDescriptor >= 0 else { throw ProcessBrokerError.outputOpenFailed }
    let input = Pipe()
    let output = Pipe()
    let errors = Pipe()
    let consent = Pipe()
    let childEvidence: Int32 = 198
    let childConsent: Int32 = 199
    var actions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&actions) == 0 else {
      close(evidenceDescriptor)
      throw ProcessBrokerError.spawnSetupFailed
    }
    defer { posix_spawn_file_actions_destroy(&actions) }
    let mappings = [
      (input.fileHandleForReading.fileDescriptor, STDIN_FILENO),
      (output.fileHandleForWriting.fileDescriptor, STDOUT_FILENO),
      (errors.fileHandleForWriting.fileDescriptor, STDERR_FILENO),
      (evidenceDescriptor, childEvidence),
      (consent.fileHandleForReading.fileDescriptor, childConsent),
    ]
    for (source, destination) in mappings {
      guard posix_spawn_file_actions_adddup2(&actions, source, destination) == 0 else {
        close(evidenceDescriptor)
        throw ProcessBrokerError.spawnSetupFailed
      }
    }
    let descriptors = Set([
      input.fileHandleForReading.fileDescriptor, input.fileHandleForWriting.fileDescriptor,
      output.fileHandleForReading.fileDescriptor, output.fileHandleForWriting.fileDescriptor,
      errors.fileHandleForReading.fileDescriptor, errors.fileHandleForWriting.fileDescriptor,
      consent.fileHandleForReading.fileDescriptor, consent.fileHandleForWriting.fileDescriptor,
      evidenceDescriptor,
    ]).subtracting([STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, childEvidence, childConsent])
    for descriptor in descriptors {
      guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else {
        close(evidenceDescriptor)
        throw ProcessBrokerError.spawnSetupFailed
      }
    }
    let arguments = [
      helperURL.path, "--capture", "--evidence-fd=\(childEvidence)",
      "--consent-fd=\(childConsent)",
    ]
    var pointers = arguments.map { strdup($0) } + [nil]
    defer { pointers.dropLast().forEach { free($0) } }
    var pid: pid_t = 0
    let status = posix_spawn(&pid, helperURL.path, &actions, nil, &pointers, environ)
    close(evidenceDescriptor)
    input.fileHandleForReading.closeFile()
    output.fileHandleForWriting.closeFile()
    errors.fileHandleForWriting.closeFile()
    consent.fileHandleForReading.closeFile()
    guard status == 0 else {
      input.fileHandleForWriting.closeFile()
      output.fileHandleForReading.closeFile()
      errors.fileHandleForReading.closeFile()
      consent.fileHandleForWriting.closeFile()
      try? FileManager.default.removeItem(at: evidenceURL)
      throw ProcessBrokerError.spawnFailed
    }
    processID = pid
    inputHandle = input.fileHandleForWriting
    consentHandle = consent.fileHandleForWriting
    outputHandle = output.fileHandleForReading
    errorHandle = errors.fileHandleForReading
    _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
    _ = fcntl(consent.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
    let readers = installReaders(onMessage: onMessage)
    let childPID = pid
    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      var waitStatus: Int32 = 0
      _ = waitpid(childPID, &waitStatus, 0)
      readers.wait()
      let signal = waitStatus & 0x7F
      let exitCode: Int32 = signal == 0 ? ((waitStatus >> 8) & 0xFF) : -signal
      onExit(exitCode, self?.finishAndCollectDiagnostics() ?? "")
    }
    do {
      try consent.fileHandleForWriting.write(contentsOf: Data("\(consentCapability)\n".utf8))
      consent.fileHandleForWriting.closeFile()
      var config = try JSONSerialization.data(withJSONObject: [
        "protocol_version": 1,
        "capture_session": captureSession,
        "process_id": candidate.processIdentifier,
        "process_bundle_id": candidate.bundleIdentifier,
        "interval_ms": intervalMilliseconds,
        "maximum_samples": maximumSamples,
      ], options: [.sortedKeys])
      config.append(0x0A)
      try input.fileHandleForWriting.write(contentsOf: config)
    } catch {
      _ = kill(pid, SIGTERM)
      throw error
    }
  }

  func stop() throws {
    try lock.withLock {
      guard processID != nil, let inputHandle else { throw ProcessBrokerError.notRunning }
      try inputHandle.write(contentsOf: Data("stop\n".utf8))
      inputHandle.closeFile()
      self.inputHandle = nil
    }
  }

  func terminate() {
    lock.withLock {
      if let processID { _ = kill(processID, SIGTERM) }
      inputHandle?.closeFile()
      consentHandle?.closeFile()
      inputHandle = nil
      consentHandle = nil
    }
  }

  private func installReaders(onMessage: @escaping MessageHandler) -> DispatchGroup {
    let group = DispatchGroup()
    if let outputHandle {
      let descriptor = outputHandle.fileDescriptor
      group.enter()
      DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        defer { group.leave() }
        while let data = readProcessBytes(from: descriptor) {
          self?.consumeOutput(data, onMessage: onMessage)
        }
      }
    }
    if let errorHandle {
      let descriptor = errorHandle.fileDescriptor
      group.enter()
      DispatchQueue.global(qos: .utility).async { [weak self] in
        defer { group.leave() }
        while let data = readProcessBytes(from: descriptor) {
          self?.lock.withLock { self?.errorBuffer.append(data) }
        }
      }
    }
    return group
  }

  private func consumeOutput(_ data: Data, onMessage: MessageHandler) {
    let lines: [Data] = lock.withLock {
      outputBuffer.append(data)
      var complete: [Data] = []
      while let newline = outputBuffer.firstIndex(of: 0x0A) {
        complete.append(outputBuffer[..<newline])
        outputBuffer.removeSubrange(...newline)
      }
      return complete
    }
    for line in lines where !line.isEmpty {
      if let message = try? JSONDecoder().decode(ProcessBrokerMessage.self, from: line) {
        onMessage(message)
      }
    }
  }

  private func finishAndCollectDiagnostics() -> String {
    lock.withLock {
      inputHandle?.closeFile()
      consentHandle?.closeFile()
      outputHandle?.closeFile()
      errorHandle?.closeFile()
      inputHandle = nil
      consentHandle = nil
      outputHandle = nil
      errorHandle = nil
      processID = nil
      let diagnostics = String(decoding: errorBuffer.prefix(4_096), as: UTF8.self)
      errorBuffer.removeAll()
      outputBuffer.removeAll()
      return diagnostics
    }
  }
}

private func readProcessBytes(from descriptor: Int32) -> Data? {
  var buffer = [UInt8](repeating: 0, count: 4_096)
  while true {
    let count = Darwin.read(descriptor, &buffer, buffer.count)
    if count > 0 { return Data(buffer.prefix(count)) }
    if count == 0 { return nil }
    if errno != EINTR { return nil }
  }
}

private extension NSLock {
  func withLock<T>(_ body: () throws -> T) rethrows -> T {
    lock()
    defer { unlock() }
    return try body()
  }
}

enum ProcessBrokerError: LocalizedError {
  case alreadyRunning, notRunning, outputOpenFailed, spawnSetupFailed, spawnFailed

  var errorDescription: String? {
    switch self {
    case .alreadyRunning: "A process capture is already active."
    case .notRunning: "No process capture is active."
    case .outputOpenFailed: "The selected evidence destination could not be created."
    case .spawnSetupFailed: "The isolated process receiver could not be prepared."
    case .spawnFailed: "The isolated process receiver could not be launched."
    }
  }
}
