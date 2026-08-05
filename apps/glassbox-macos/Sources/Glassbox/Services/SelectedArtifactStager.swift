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
    guard source.pathExtension == "trace", sourceValues.isDirectory == true,
      sourceValues.isSymbolicLink != true
    else { throw SelectedArtifactStageError.invalidSource }

    let descriptor = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw SelectedArtifactStageError.invalidSource }
    defer { close(descriptor) }
    return try stageDirectory(
      sourceDescriptor: descriptor, pathExtension: "trace", into: stagingRoot)
  }

  static func stageDirectory(
    sourceDescriptor: Int32,
    pathExtension: String,
    into stagingRoot: URL
  ) throws -> URL {
    guard pathExtension == "trace" || pathExtension == "logarchive" else {
      throw SelectedArtifactStageError.invalidSource
    }
    var sourceMetadata = stat()
    guard fstat(sourceDescriptor, &sourceMetadata) == 0,
      (sourceMetadata.st_mode & S_IFMT) == S_IFDIR
    else { throw SelectedArtifactStageError.invalidSource }

    let rootValues = try stagingRoot.resourceValues(forKeys: [
      .isDirectoryKey, .isSymbolicLinkKey,
    ])
    guard rootValues.isDirectory == true, rootValues.isSymbolicLink != true else {
      throw SelectedArtifactStageError.invalidRoot
    }
    let canonicalStagingRoot = try canonicalExistingURL(stagingRoot)
    let destination =
      canonicalStagingRoot
      .appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
      .appendingPathExtension(pathExtension)
    try FileManager.default.createDirectory(
      at: destination, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    do {
      var state = CopyState()
      try copyDirectory(
        sourceDescriptor: sourceDescriptor,
        destination: destination,
        relativePrefix: "",
        state: &state)
      var after = stat()
      guard fstat(sourceDescriptor, &after) == 0, stable(sourceMetadata, after) else {
        throw SelectedArtifactStageError.changedDuringRead
      }
      return destination
    } catch {
      try? FileManager.default.removeItem(at: destination)
      throw error
    }
  }

  private struct CopyState {
    var entryCount = 0
    var totalBytes: UInt64 = 0
    var foldedPaths = Set<String>()
  }

  private static func copyDirectory(
    sourceDescriptor: Int32,
    destination: URL,
    relativePrefix: String,
    state: inout CopyState
  ) throws {
    let enumerationDescriptor = openat(
      sourceDescriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard enumerationDescriptor >= 0 else { throw SelectedArtifactStageError.invalidSource }
    guard let directory = fdopendir(enumerationDescriptor) else {
      close(enumerationDescriptor)
      throw SelectedArtifactStageError.invalidSource
    }
    defer { closedir(directory) }

    var names: [String] = []
    while let entry = readdir(directory) {
      let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) {
          String(validatingCString: $0)
        }
      }
      guard let name else { throw SelectedArtifactStageError.invalidRelativePath }
      if name == "." || name == ".." { continue }
      names.append(name)
    }
    names.sort { $0.utf8.lexicographicallyPrecedes($1.utf8) }

    let directoryDescriptor = dirfd(directory)
    for name in names {
      guard state.entryCount < SelectedArtifactHasher.maximumFiles else {
        throw SelectedArtifactStageError.tooManyEntries
      }
      state.entryCount += 1
      let relative = relativePrefix.isEmpty ? name : "\(relativePrefix)/\(name)"
      guard !relative.isEmpty,
        relative.utf8.count <= SelectedArtifactHasher.maximumRelativePathBytes,
        !relative.split(separator: "/").contains("..")
      else { throw SelectedArtifactStageError.invalidRelativePath }
      let folded = relative.precomposedStringWithCanonicalMapping.folding(
        options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
      guard state.foldedPaths.insert(folded).inserted else {
        throw SelectedArtifactStageError.caseCollision
      }

      var before = stat()
      let statResult = name.withCString {
        fstatat(directoryDescriptor, $0, &before, AT_SYMLINK_NOFOLLOW)
      }
      guard statResult == 0 else { throw SelectedArtifactStageError.unsupportedFileType }
      let destinationURL = destination.appendingPathComponent(
        relative, isDirectory: (before.st_mode & S_IFMT) == S_IFDIR)
      switch before.st_mode & S_IFMT {
      case S_IFDIR:
        let childDescriptor = name.withCString {
          openat(directoryDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard childDescriptor >= 0 else {
          throw SelectedArtifactStageError.unsupportedFileType
        }
        defer { close(childDescriptor) }
        var opened = stat()
        guard fstat(childDescriptor, &opened) == 0, stable(before, opened) else {
          throw SelectedArtifactStageError.changedDuringRead
        }
        try FileManager.default.createDirectory(
          at: destinationURL,
          withIntermediateDirectories: false,
          attributes: [.posixPermissions: 0o700])
        try copyDirectory(
          sourceDescriptor: childDescriptor,
          destination: destination,
          relativePrefix: relative,
          state: &state)
        var after = stat()
        guard fstat(childDescriptor, &after) == 0, stable(opened, after) else {
          throw SelectedArtifactStageError.changedDuringRead
        }
      case S_IFREG:
        try copyRegularFile(
          parentDescriptor: directoryDescriptor,
          name: name,
          before: before,
          destination: destinationURL,
          state: &state)
      default:
        throw SelectedArtifactStageError.unsupportedFileType
      }
    }
  }

  private static func copyRegularFile(
    parentDescriptor: Int32,
    name: String,
    before: stat,
    destination: URL,
    state: inout CopyState
  ) throws {
    let sourceDescriptor = name.withCString {
      openat(parentDescriptor, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard sourceDescriptor >= 0 else { throw SelectedArtifactStageError.unsupportedFileType }
    defer { close(sourceDescriptor) }
    var metadata = stat()
    guard fstat(sourceDescriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_size >= 0, stable(before, metadata)
    else { throw SelectedArtifactStageError.changedDuringRead }
    let size = UInt64(metadata.st_size)
    let (nextTotal, overflow) = state.totalBytes.addingReportingOverflow(size)
    guard !overflow, nextTotal <= SelectedArtifactHasher.maximumBytes else {
      throw SelectedArtifactStageError.artifactTooLarge
    }
    state.totalBytes = nextTotal
    let destinationDescriptor = open(
      destination.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
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
    var after = stat()
    guard fstat(sourceDescriptor, &after) == 0, stable(metadata, after)
    else { throw SelectedArtifactStageError.changedDuringRead }
    try destinationHandle.synchronize()
  }

  private static func stable(_ left: stat, _ right: stat) -> Bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
      && (left.st_mode & S_IFMT) == (right.st_mode & S_IFMT)
      && left.st_size == right.st_size
      && left.st_mtimespec.tv_sec == right.st_mtimespec.tv_sec
      && left.st_mtimespec.tv_nsec == right.st_mtimespec.tv_nsec
      && left.st_ctimespec.tv_sec == right.st_ctimespec.tv_sec
      && left.st_ctimespec.tv_nsec == right.st_ctimespec.tv_nsec
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
