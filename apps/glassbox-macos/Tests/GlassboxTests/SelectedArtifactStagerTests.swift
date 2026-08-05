import Foundation
import Testing
@testable import Glassbox

@Test func traceStagingCopiesOnlyRegularContentWithOpaqueNamesAndSafeModes() throws {
  let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let source = base.appendingPathComponent("selected.trace", isDirectory: true)
  let staging = base.appendingPathComponent("staging", isDirectory: true)
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: base) }
  try FileManager.default.createDirectory(
    at: source.appendingPathComponent("nested"), withIntermediateDirectories: true)
  try Data("trace-data".utf8).write(to: source.appendingPathComponent("nested/data"))
  let destination = try SelectedArtifactStager.stageTrace(source: source, into: staging)
  #expect(destination.pathExtension == "trace")
  #expect(UUID(uuidString: destination.deletingPathExtension().lastPathComponent) != nil)
  #expect(
    try Data(contentsOf: destination.appendingPathComponent("nested/data"))
      == Data("trace-data".utf8))
  let attributes = try FileManager.default.attributesOfItem(
    atPath: destination.appendingPathComponent("nested/data").path)
  #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
}

@Test func traceStagingRejectsLinksAndRemovesPartialDestination() throws {
  let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let source = base.appendingPathComponent("selected.trace", isDirectory: true)
  let staging = base.appendingPathComponent("staging", isDirectory: true)
  try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
  try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: base) }
  try Data("target".utf8).write(to: source.appendingPathComponent("target"))
  try FileManager.default.createSymbolicLink(
    at: source.appendingPathComponent("link"),
    withDestinationURL: source.appendingPathComponent("target"))
  #expect(throws: SelectedArtifactStageError.unsupportedFileType) {
    try SelectedArtifactStager.stageTrace(source: source, into: staging)
  }
  #expect((try FileManager.default.contentsOfDirectory(atPath: staging.path)).isEmpty)
}
