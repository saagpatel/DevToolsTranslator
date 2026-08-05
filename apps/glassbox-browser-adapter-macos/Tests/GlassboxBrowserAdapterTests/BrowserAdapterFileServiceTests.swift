import Foundation
import Testing
@testable import GlassboxBrowserAdapter

@Suite("Browser adapter owned-state lifecycle")
struct BrowserAdapterFileServiceTests {
  @Test("manifest is exact, private, replaceable, and removable without touching exports")
  func manifestLifecycle() throws {
    let temp = try TemporaryHome()
    defer { temp.remove() }
    let service = BrowserAdapterFileService(home: temp.url)
    let host = temp.url.appendingPathComponent("Glassbox Browser Adapter.app/Contents/Helpers/glassbox-browser-host")
    try FileManager.default.createDirectory(at: host.deletingLastPathComponent(), withIntermediateDirectories: true)
    XCTAssertTrue(FileManager.default.createFile(atPath: host.path, contents: Data("host".utf8)))
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: host.path)
    try service.installManifest(hostURL: host)
    let manifest = try JSONDecoder().decode(
      NativeHostManifest.self, from: Data(contentsOf: service.manifestURL))
    #expect(manifest == .production(hostPath: host.path))
    let mode = try service.manifestURL.resourceValues(forKeys: [.fileSecurityKey]).fileSecurity
    #expect(mode != nil)
    try service.installManifest(hostURL: host)
    let userExport = temp.url.appendingPathComponent("Documents/user.glassbox")
    try FileManager.default.createDirectory(at: userExport.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data("user-export".utf8).write(to: userExport)
    try service.resetManifest()
    #expect(!FileManager.default.fileExists(atPath: service.manifestURL.path))
    #expect(try Data(contentsOf: userExport) == Data("user-export".utf8))
  }

  @Test("only regular owned bundles are listed and exports never overwrite")
  func inboxAndExport() throws {
    let temp = try TemporaryHome()
    defer { temp.remove() }
    let service = BrowserAdapterFileService(home: temp.url)
    try FileManager.default.createDirectory(at: service.inboxURL, withIntermediateDirectories: true)
    let bundle = service.inboxURL.appendingPathComponent("session.glassbox")
    try Data("GLSBX001fixture".utf8).write(to: bundle)
    try Data("partial".utf8).write(to: service.inboxURL.appendingPathComponent(".session.partial"))
    let items = try service.items()
    #expect(items.map(\.id) == ["session.glassbox"])
    let destination = temp.url.appendingPathComponent("Documents/export.glassbox")
    try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
    try service.export(item: items[0], to: destination)
    #expect(try Data(contentsOf: destination) == Data("GLSBX001fixture".utf8))
    #expect(throws: BrowserAdapterFileError.self) {
      try service.export(item: items[0], to: destination)
    }
    try service.deleteOwned(item: items[0])
    #expect(!FileManager.default.fileExists(atPath: bundle.path))
    #expect(FileManager.default.fileExists(atPath: destination.path))
  }
}

private struct TemporaryHome {
  let url: URL
  init() throws {
    url = FileManager.default.temporaryDirectory
      .appendingPathComponent("glassbox-browser-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
  }
  func remove() { try? FileManager.default.removeItem(at: url) }
}

private func XCTAssertTrue(_ value: Bool) { #expect(value) }
