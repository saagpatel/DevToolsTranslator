import Foundation
import Testing
@testable import Glassbox

@Test func boundedProcessTerminatesOnDeadline() throws {
  let clock = ContinuousClock()
  let started = clock.now
  #expect(throws: BoundedProcessError.timedOut) {
    try BoundedProcess.run(
      executable: URL(fileURLWithPath: "/bin/sleep"),
      arguments: ["5"],
      timeout: .milliseconds(50))
  }
  #expect(started.duration(to: clock.now) < .seconds(2))
}

@Test func instrumentsAdapterRequiresOpaqueDirectStagingNames() throws {
  let root = URL(fileURLWithPath: "/tmp/glassbox-stage", isDirectory: true)
  let adapter = InstrumentsTraceAdapter(xctraceURL: URL(fileURLWithPath: "/usr/bin/false"))
  #expect(throws: InstrumentsTraceAdapterError.invalidStagingPath) {
    try adapter.exportNetworkHAR(
      stagedTrace: URL(fileURLWithPath: "/Users/example/private.trace"),
      outputHAR: root.appendingPathComponent("output.har"),
      stagingRoot: root)
  }
}
