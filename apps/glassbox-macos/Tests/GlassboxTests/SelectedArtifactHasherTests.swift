import Foundation
import Testing
@testable import Glassbox

@Test func selectedArtifactHashIsDeterministicAndContentBound() throws {
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString)
    .appendingPathExtension("logarchive")
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: root) }
  try Data("one".utf8).write(to: root.appendingPathComponent("a"))
  try FileManager.default.createDirectory(
    at: root.appendingPathComponent("nested"), withIntermediateDirectories: true)
  let second = root.appendingPathComponent("nested/b")
  try Data("two".utf8).write(to: second)
  let first = try SelectedArtifactHasher.sha256(directory: root)
  #expect(first == (try SelectedArtifactHasher.sha256(directory: root)))
  try Data("changed".utf8).write(to: second)
  #expect(first != (try SelectedArtifactHasher.sha256(directory: root)))
}

@Test func selectedArtifactHashRejectsSymlinks() throws {
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString)
    .appendingPathExtension("logarchive")
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: root) }
  try Data("target".utf8).write(to: root.appendingPathComponent("target"))
  try FileManager.default.createSymbolicLink(
    at: root.appendingPathComponent("link"),
    withDestinationURL: root.appendingPathComponent("target"))
  #expect(throws: SelectedArtifactHashError.unsupportedFileType) {
    try SelectedArtifactHasher.sha256(directory: root)
  }
}

@Test func selectedRegularFileHashIsRawContentBoundAndRewound() throws {
  let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try Data("abc".utf8).write(to: file)
  defer { try? FileManager.default.removeItem(at: file) }
  let selected = try SelectedArtifactHasher.openAndHash(file: file, maximumBytes: 16)
  defer { try? selected.handle.close() }
  #expect(selected.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  #expect(selected.size == 3)
  #expect(try selected.handle.readToEnd() == Data("abc".utf8))
}

@Test func selectedRegularFileHashRejectsOversizeAndLinks() throws {
  let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: base) }
  let file = base.appendingPathComponent("source")
  let link = base.appendingPathComponent("link")
  try Data("oversize".utf8).write(to: file)
  try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
  #expect(throws: SelectedArtifactHashError.artifactTooLarge) {
    try SelectedArtifactHasher.openAndHash(file: file, maximumBytes: 2)
  }
  #expect(throws: SelectedArtifactHashError.unsupportedFileType) {
    try SelectedArtifactHasher.openAndHash(file: link, maximumBytes: 64)
  }
}
