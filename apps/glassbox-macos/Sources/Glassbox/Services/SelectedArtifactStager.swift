import Darwin
import Foundation

enum SelectedArtifactStageError: Error, Equatable {
  case invalidRoot
  case invalidSource
  case tooManyEntries
  case artifactTooLarge
  case invalidRelativePath
  case caseCollision
  case unsupportedFileType
  case changedDuringRead
}

enum SelectedArtifactStager {
  static func stageTrace(source: URL, into stagingRoot: URL) throws -> URL {
    let sourceValues = try source.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
    let rootValues = try stagingRoot.resourceValues(forKeys: [
      .isDirectoryKey, .isSymbolicLinkKey,
    ])
    guard source.pathExtension == "trace", sourceValues.isDirectory == true,
      sourceValues.isSymbolicLink != true
    else { throw SelectedArtifactStageError.invalidSource }
    guard rootValues.isDirectory == true, rootValues.isSymbolicLink != true else {
      throw SelectedArtifactStageError.invalidRoot
    }
    // FileManager may enumerate the canonical `/private/var/...` spelling even when
    // the selected URL arrived through `/var/...`. Use filesystem identity before
    // deriving relative paths so an alias cannot manufacture a partial component.
    let canonicalSource = try canonicalExistingURL(source)
    let canonicalStagingRoot = try canonicalExistingURL(stagingRoot)
    let destination = canonicalStagingRoot
      .appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
      .appendingPathExtension("trace")
    try FileManager.default.createDirectory(
      at: destination, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    do {
      try copyTree(source: canonicalSource, destination: destination)
      return destination
    } catch {
      try? FileManager.default.removeItem(at: destination)
      throw error
    }
  }

  private static func copyTree(source: URL, destination: URL) throws {
    var enumerationFailed = false
    guard
      let enumerator = FileManager.default.enumerator(
        at: source,
        includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
        options: [],
        errorHandler: { _, _ in
          enumerationFailed = true
          return false
        })
    else { throw SelectedArtifactStageError.invalidSource }
    var directories: [(String, URL)] = []
    var files: [(String, URL)] = []
    var foldedPaths = Set<String>()
    for case let url as URL in enumerator {
      guard directories.count + files.count < SelectedArtifactHasher.maximumFiles else {
        throw SelectedArtifactStageError.tooManyEntries
      }
      let values = try url.resourceValues(forKeys: [
        .isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey,
      ])
      guard values.isSymbolicLink != true else {
        throw SelectedArtifactStageError.unsupportedFileType
      }
      let canonicalURL = try canonicalExistingURL(url)
      let prefix = source.path + "/"
      guard canonicalURL.path.hasPrefix(prefix) else {
        throw SelectedArtifactStageError.invalidRelativePath
      }
      let relative = String(canonicalURL.path.dropFirst(prefix.count))
      guard !relative.isEmpty,
        relative.utf8.count <= SelectedArtifactHasher.maximumRelativePathBytes,
        !relative.split(separator: "/").contains("..")
      else { throw SelectedArtifactStageError.invalidRelativePath }
      let folded = relative.precomposedStringWithCanonicalMapping.folding(
        options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
      guard foldedPaths.insert(folded).inserted else {
        throw SelectedArtifactStageError.caseCollision
      }
      if values.isDirectory == true {
        directories.append((relative, canonicalURL))
      } else if values.isRegularFile == true {
        files.append((relative, canonicalURL))
      } else {
        throw SelectedArtifactStageError.unsupportedFileType
      }
    }
    guard !enumerationFailed else { throw SelectedArtifactStageError.invalidSource }
    directories.sort {
      let leftDepth = $0.0.split(separator: "/").count
      let rightDepth = $1.0.split(separator: "/").count
      return leftDepth == rightDepth ? $0.0 < $1.0 : leftDepth < rightDepth
    }
    for (relative, _) in directories {
      try FileManager.default.createDirectory(
        at: destination.appendingPathComponent(relative, isDirectory: true),
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700])
    }
    files.sort { $0.0.utf8.lexicographicallyPrecedes($1.0.utf8) }
    var totalBytes: UInt64 = 0
    for (relative, sourceFile) in files {
      let destinationFile = destination.appendingPathComponent(relative, isDirectory: false)
      let sourceDescriptor = open(sourceFile.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      guard sourceDescriptor >= 0 else { throw SelectedArtifactStageError.unsupportedFileType }
      defer { close(sourceDescriptor) }
      var metadata = stat()
      guard fstat(sourceDescriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
        metadata.st_size >= 0
      else { throw SelectedArtifactStageError.unsupportedFileType }
      let size = UInt64(metadata.st_size)
      let (nextTotal, overflow) = totalBytes.addingReportingOverflow(size)
      guard !overflow, nextTotal <= SelectedArtifactHasher.maximumBytes else {
        throw SelectedArtifactStageError.artifactTooLarge
      }
      totalBytes = nextTotal
      let destinationDescriptor = open(
        destinationFile.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
      guard destinationDescriptor >= 0 else {
        throw SelectedArtifactStageError.unsupportedFileType
      }
      defer { close(destinationDescriptor) }
      let sourceHandle = FileHandle(fileDescriptor: sourceDescriptor, closeOnDealloc: false)
      let destinationHandle = FileHandle(fileDescriptor: destinationDescriptor, closeOnDealloc: false)
      var copied: UInt64 = 0
      while let chunk = try sourceHandle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
        copied += UInt64(chunk.count)
        guard copied <= size else { throw SelectedArtifactStageError.changedDuringRead }
        try destinationHandle.write(contentsOf: chunk)
      }
      guard copied == size else { throw SelectedArtifactStageError.changedDuringRead }
      try destinationHandle.synchronize()
    }
  }

  private static func canonicalExistingURL(_ url: URL) throws -> URL {
    let resolved: UnsafeMutablePointer<CChar>? = url.withUnsafeFileSystemRepresentation { path in
      guard let path else { return nil }
      return realpath(path, nil)
    }
    guard let resolved else { throw SelectedArtifactStageError.invalidSource }
    defer { free(resolved) }
    return URL(fileURLWithFileSystemRepresentation: resolved, isDirectory: true, relativeTo: nil)
      .standardizedFileURL
  }
}
