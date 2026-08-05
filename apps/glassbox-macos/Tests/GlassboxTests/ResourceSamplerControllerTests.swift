import Foundation
import Testing

@testable import Glassbox

struct ResourceSamplerControllerTests {
  @Test("a stop requested before helper launch is delivered exactly once")
  func prelaunchStopIsLatched() throws {
    let controller = ResourceSamplerController()
    controller.arm()
    controller.stop()

    let frame = try controller.withStopInput { input in
      let data = try input.read(upToCount: 6)
      return try #require(data)
    }

    #expect(frame == Data("stop\n".utf8))
  }
}
