import Foundation

/// Owns the one inherited pipe that can stop an active bounded helper session.
/// The lock makes the controller safe to call from the main actor and the
/// detached helper task without exposing Process or a filesystem path.
final class ResourceSamplerController: @unchecked Sendable {
  private enum Phase { case idle, starting, active }

  private let lock = NSLock()
  private var phase = Phase.idle
  private var stopRequested = false
  private var stopHandle: FileHandle?

  /// Arms the controller before detached work begins, so an immediate user
  /// stop cannot race past helper launch.
  func arm() {
    lock.withLock {
      phase = .starting
      stopRequested = false
      stopHandle = nil
    }
  }

  func sample(
    service: RustEvidenceService,
    captureSession: UUID,
    intervalMilliseconds: UInt64 = 500,
    maximumSamples: Int = 60
  ) throws -> NativeShellPayload {
    try withStopInput { stopInput in
      try service.loadResourceSample(
        stopInput: stopInput,
        captureSession: captureSession,
        intervalMilliseconds: intervalMilliseconds,
        maximumSamples: maximumSamples)
    }
  }

  /// Internal seam used by the service and the race regression test. The only
  /// protocol value this controller can write is the fixed `stop` frame.
  func withStopInput<T>(_ operation: (FileHandle) throws -> T) rethrows -> T {
    let pipe = Pipe()
    let stopWasRequested = lock.withLock {
      phase = .active
      stopHandle = pipe.fileHandleForWriting
      return stopRequested
    }
    if stopWasRequested {
      try? pipe.fileHandleForWriting.write(contentsOf: Data("stop\n".utf8))
      try? pipe.fileHandleForWriting.close()
    }
    defer {
      try? pipe.fileHandleForWriting.close()
      try? pipe.fileHandleForReading.close()
      lock.withLock {
        phase = .idle
        stopRequested = false
        stopHandle = nil
      }
    }
    return try operation(pipe.fileHandleForReading)
  }

  func stop() {
    let handle = lock.withLock { () -> FileHandle? in
      switch phase {
      case .idle:
        return nil
      case .starting:
        stopRequested = true
        return nil
      case .active:
        let handle = stopHandle
        stopHandle = nil
        return handle
      }
    }
    guard let handle else { return }
    try? handle.write(contentsOf: Data("stop\n".utf8))
    try? handle.close()
  }
}
