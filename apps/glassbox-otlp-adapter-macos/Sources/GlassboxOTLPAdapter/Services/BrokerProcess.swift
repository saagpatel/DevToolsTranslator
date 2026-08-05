import Darwin
import Foundation

final class BrokerProcess: @unchecked Sendable {
  typealias MessageHandler = @Sendable (BrokerMessage) -> Void
  typealias ExitHandler = @Sendable (Int32, String) -> Void

  private let lock = NSLock()
  private var processID: pid_t?
  private var inputHandle: FileHandle?
  private var outputHandle: FileHandle?
  private var errorHandle: FileHandle?
  private var outputBuffer = Data()
  private var errorBuffer = Data()

  func start(
    helperURL: URL,
    evidenceURL: URL,
    configuration: BrokerConfiguration,
    onMessage: @escaping MessageHandler,
    onExit: @escaping ExitHandler
  ) throws {
    lock.lock()
    defer { lock.unlock() }
    guard processID == nil else { throw BrokerProcessError.alreadyRunning }

    let evidenceDescriptor = open(evidenceURL.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
    guard evidenceDescriptor >= 0 else {
      throw BrokerProcessError.outputOpenFailed(errno)
    }
    var actions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&actions) == 0 else {
      close(evidenceDescriptor)
      throw BrokerProcessError.spawnSetupFailed
    }
    defer { posix_spawn_file_actions_destroy(&actions) }

    let input = Pipe()
    let output = Pipe()
    let errors = Pipe()
    let childEvidenceDescriptor: Int32 = 3
    let mappings = [
      (input.fileHandleForReading.fileDescriptor, STDIN_FILENO),
      (output.fileHandleForWriting.fileDescriptor, STDOUT_FILENO),
      (errors.fileHandleForWriting.fileDescriptor, STDERR_FILENO),
      (evidenceDescriptor, childEvidenceDescriptor),
    ]
    for (source, destination) in mappings {
      guard posix_spawn_file_actions_adddup2(&actions, source, destination) == 0 else {
        close(evidenceDescriptor)
        throw BrokerProcessError.spawnSetupFailed
      }
    }
    let descriptorsToClose = Set([
      input.fileHandleForReading.fileDescriptor,
      input.fileHandleForWriting.fileDescriptor,
      output.fileHandleForReading.fileDescriptor,
      output.fileHandleForWriting.fileDescriptor,
      errors.fileHandleForReading.fileDescriptor,
      errors.fileHandleForWriting.fileDescriptor,
      evidenceDescriptor,
    ]).subtracting([STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, childEvidenceDescriptor])
    for descriptor in descriptorsToClose {
      guard posix_spawn_file_actions_addclose(&actions, descriptor) == 0 else {
        close(evidenceDescriptor)
        throw BrokerProcessError.spawnSetupFailed
      }
    }

    let arguments = [helperURL.path, "--evidence-fd=\(childEvidenceDescriptor)"]
    var argumentPointers = arguments.map { strdup($0) } + [nil]
    defer { argumentPointers.dropLast().forEach { free($0) } }
    var pid: pid_t = 0
    let spawnStatus = posix_spawn(
      &pid,
      helperURL.path,
      &actions,
      nil,
      &argumentPointers,
      environ
    )
    close(evidenceDescriptor)
    input.fileHandleForReading.closeFile()
    output.fileHandleForWriting.closeFile()
    errors.fileHandleForWriting.closeFile()
    guard spawnStatus == 0 else {
      input.fileHandleForWriting.closeFile()
      output.fileHandleForReading.closeFile()
      errors.fileHandleForReading.closeFile()
      try? FileManager.default.removeItem(at: evidenceURL)
      throw BrokerProcessError.spawnFailed(spawnStatus)
    }

    processID = pid
    inputHandle = input.fileHandleForWriting
    _ = fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1)
    outputHandle = output.fileHandleForReading
    errorHandle = errors.fileHandleForReading
    let readers = installReaders(onMessage: onMessage)

    do {
      var encoded = try JSONEncoder().encode(configuration)
      encoded.append(0x0A)
      try input.fileHandleForWriting.write(contentsOf: encoded)
    } catch {
      _ = kill(pid, SIGTERM)
      input.fileHandleForWriting.closeFile()
      try? FileManager.default.removeItem(at: evidenceURL)
      throw error
    }

    let childProcessID = pid
    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      var status: Int32 = 0
      _ = waitpid(childProcessID, &status, 0)
      readers.wait()
      let signal = status & 0x7F
      let exitCode: Int32 = signal == 0 ? ((status >> 8) & 0xFF) : -signal
      let diagnostics = self?.finishAndCollectDiagnostics() ?? ""
      onExit(exitCode, diagnostics)
    }
  }

  func stop() throws {
    lock.lock()
    defer { lock.unlock() }
    guard let inputHandle else { throw BrokerProcessError.notRunning }
    let control = Array("stop\n".utf8)
    let count = Darwin.write(inputHandle.fileDescriptor, control, control.count)
    guard count == control.count else {
      if count < 0, errno == EPIPE { throw BrokerProcessError.notRunning }
      throw BrokerProcessError.controlWriteFailed
    }
  }

  func terminate() {
    lock.withLock {
      if let processID { _ = kill(processID, SIGTERM) }
      inputHandle?.closeFile()
    }
  }

  private func installReaders(onMessage: @escaping MessageHandler) -> DispatchGroup {
    let readers = DispatchGroup()
    if let outputHandle {
      let descriptor = outputHandle.fileDescriptor
      readers.enter()
      DispatchQueue.global(qos: .userInitiated).async { [weak self] in
        defer { readers.leave() }
        while let data = readAvailableBytes(from: descriptor) {
          self?.consumeOutput(data, onMessage: onMessage)
        }
      }
    }
    if let errorHandle {
      let descriptor = errorHandle.fileDescriptor
      readers.enter()
      DispatchQueue.global(qos: .utility).async { [weak self] in
        defer { readers.leave() }
        while let data = readAvailableBytes(from: descriptor) {
          self?.lock.withLock { self?.errorBuffer.append(data) }
        }
      }
    }
    return readers
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
      if let message = try? JSONDecoder().decode(BrokerMessage.self, from: line) {
        onMessage(message)
      }
    }
  }

  private func finishAndCollectDiagnostics() -> String {
    lock.withLock {
      inputHandle?.closeFile()
      outputHandle?.closeFile()
      errorHandle?.closeFile()
      inputHandle = nil
      outputHandle = nil
      errorHandle = nil
      processID = nil
      let diagnostics = String(decoding: errorBuffer.prefix(4_096), as: UTF8.self)
      errorBuffer.removeAll(keepingCapacity: false)
      outputBuffer.removeAll(keepingCapacity: false)
      return diagnostics
    }
  }
}

private func readAvailableBytes(from descriptor: Int32) -> Data? {
  var buffer = [UInt8](repeating: 0, count: 4_096)
  while true {
    let count = Darwin.read(descriptor, &buffer, buffer.count)
    if count > 0 { return Data(buffer.prefix(count)) }
    if count == 0 { return nil }
    if errno != EINTR { return nil }
  }
}

private extension NSLock {
  func withLock<T>(_ body: () -> T) -> T {
    lock()
    defer { unlock() }
    return body()
  }
}

enum BrokerProcessError: LocalizedError {
  case alreadyRunning
  case notRunning
  case outputOpenFailed(Int32)
  case controlWriteFailed
  case spawnSetupFailed
  case spawnFailed(Int32)

  var errorDescription: String? {
    switch self {
    case .alreadyRunning: "A capture is already active."
    case .notRunning: "No capture is active."
    case .outputOpenFailed: "The selected evidence destination could not be created."
    case .controlWriteFailed: "The isolated receiver could not be stopped cleanly."
    case .spawnSetupFailed: "The isolated receiver could not be prepared."
    case .spawnFailed: "The isolated receiver could not be launched."
    }
  }
}
