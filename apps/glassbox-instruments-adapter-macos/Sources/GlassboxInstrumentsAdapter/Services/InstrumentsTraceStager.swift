import CryptoKit
import Darwin
import Foundation

enum InstrumentsTraceStager {
  static let maximumEntries = 100_000
  static let maximumBytes: UInt64 = 64 * 1024 * 1024 * 1024
  static let maximumPathBytes = 4_096

  private struct CopyState {
    var entryCount = 0
    var totalBytes: UInt64 = 0
    var foldedPaths = Set<String>()
  }

  static func stage(sourceDescriptor: Int32, into stagingRoot: URL) throws -> URL {
    var sourceMetadata = stat()
    guard fstat(sourceDescriptor, &sourceMetadata) == 0,
      (sourceMetadata.st_mode & S_IFMT) == S_IFDIR
    else { throw InstrumentsConversionError.invalidSource }

    let rootValues = try stagingRoot.resourceValues(forKeys: [
      .isDirectoryKey, .isSymbolicLinkKey,
    ])
    guard rootValues.isDirectory == true, rootValues.isSymbolicLink != true else {
      throw InstrumentsConversionError.sourceRejected
    }
    let destination = stagingRoot.appendingPathComponent(
      "\(UUID().uuidString.lowercased()).trace", isDirectory: true)
    try FileManager.default.createDirectory(
      at: destination,
      withIntermediateDirectories: false,
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
        throw InstrumentsConversionError.sourceChanged
      }
      return destination
    } catch {
      try? FileManager.default.removeItem(at: destination)
      throw error
    }
  }

  static func sha256(directory root: URL) throws -> String {
    let canonicalRoot = root.resolvingSymlinksInPath().standardizedFileURL
    let prefix = canonicalRoot.path + "/"
    var failed = false
    guard
      let enumerator = FileManager.default.enumerator(
        at: canonicalRoot,
        includingPropertiesForKeys: [
          .isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey,
        ],
        options: [],
        errorHandler: { _, _ in
          failed = true
          return false
        })
    else { throw InstrumentsConversionError.sourceRejected }
    var files: [(relative: String, url: URL)] = []
    for case let url as URL in enumerator {
      let values = try url.resourceValues(forKeys: [
        .isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey,
      ])
      guard values.isSymbolicLink != true else {
        throw InstrumentsConversionError.sourceRejected
      }
      if values.isDirectory == true { continue }
      guard values.isRegularFile == true, files.count < maximumEntries else {
        throw InstrumentsConversionError.sourceRejected
      }
      let canonicalURL = url.resolvingSymlinksInPath().standardizedFileURL
      guard canonicalURL.path.hasPrefix(prefix) else {
        throw InstrumentsConversionError.sourceRejected
      }
      let relative = String(canonicalURL.path.dropFirst(prefix.count))
      guard valid(relative: relative) else {
        throw InstrumentsConversionError.sourceRejected
      }
      files.append((relative, canonicalURL))
    }
    guard !failed else { throw InstrumentsConversionError.sourceRejected }
    files.sort { $0.relative.utf8.lexicographicallyPrecedes($1.relative.utf8) }
    var digest = SHA256()
    digest.update(data: Data("glassbox-selected-directory-v1\0".utf8))
    var totalBytes: UInt64 = 0
    for file in files {
      let descriptor = open(file.url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      guard descriptor >= 0 else { throw InstrumentsConversionError.sourceRejected }
      defer { close(descriptor) }
      var before = stat()
      guard fstat(descriptor, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
        before.st_size >= 0
      else { throw InstrumentsConversionError.sourceRejected }
      let size = UInt64(before.st_size)
      let (nextTotal, overflow) = totalBytes.addingReportingOverflow(size)
      guard !overflow, nextTotal <= maximumBytes else {
        throw InstrumentsConversionError.sourceTooLarge
      }
      totalBytes = nextTotal
      updateLengthPrefixed(Data(file.relative.utf8), digest: &digest)
      digest.update(data: withUnsafeBytes(of: size.bigEndian) { Data($0) })
      let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
      var copied: UInt64 = 0
      while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty {
        copied += UInt64(chunk.count)
        guard copied <= size else { throw InstrumentsConversionError.sourceRejected }
        digest.update(data: chunk)
      }
      var after = stat()
      guard copied == size, fstat(descriptor, &after) == 0, stable(before, after) else {
        throw InstrumentsConversionError.sourceRejected
      }
    }
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
  }

  private static func copyDirectory(
    sourceDescriptor: Int32,
    destination: URL,
    relativePrefix: String,
    state: inout CopyState
  ) throws {
    let enumerationDescriptor = openat(
      sourceDescriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard enumerationDescriptor >= 0, let directory = fdopendir(enumerationDescriptor) else {
      if enumerationDescriptor >= 0 { close(enumerationDescriptor) }
      throw InstrumentsConversionError.sourceRejected
    }
    defer { closedir(directory) }
    var directoryBefore = stat()
    guard fstat(dirfd(directory), &directoryBefore) == 0 else {
      throw InstrumentsConversionError.sourceRejected
    }

    var names: [String] = []
    while let entry = readdir(directory) {
      let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: Int(NAME_MAX) + 1) {
          String(validatingCString: $0)
        }
      }
      guard let name else { throw InstrumentsConversionError.sourceRejected }
      if name != "." && name != ".." { names.append(name) }
    }
    names.sort { $0.utf8.lexicographicallyPrecedes($1.utf8) }

    let directoryDescriptor = dirfd(directory)
    for name in names {
      guard state.entryCount < maximumEntries else {
        throw InstrumentsConversionError.tooManyEntries
      }
      state.entryCount += 1
      let relative = relativePrefix.isEmpty ? name : "\(relativePrefix)/\(name)"
      guard valid(relative: relative) else {
        throw InstrumentsConversionError.sourceRejected
      }
      let folded = relative.precomposedStringWithCanonicalMapping.folding(
        options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
      guard state.foldedPaths.insert(folded).inserted else {
        throw InstrumentsConversionError.sourceRejected
      }

      var before = stat()
      let statResult = name.withCString {
        fstatat(directoryDescriptor, $0, &before, AT_SYMLINK_NOFOLLOW)
      }
      guard statResult == 0 else { throw InstrumentsConversionError.sourceRejected }
      let destinationURL = destination.appendingPathComponent(
        relative, isDirectory: (before.st_mode & S_IFMT) == S_IFDIR)
      switch before.st_mode & S_IFMT {
      case S_IFDIR:
        let childDescriptor = name.withCString {
          openat(directoryDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard childDescriptor >= 0 else { throw InstrumentsConversionError.sourceRejected }
        defer { close(childDescriptor) }
        var opened = stat()
        guard fstat(childDescriptor, &opened) == 0, stable(before, opened) else {
          throw InstrumentsConversionError.sourceChanged
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
          throw InstrumentsConversionError.sourceChanged
        }
      case S_IFREG:
        try copyRegularFile(
          parentDescriptor: directoryDescriptor,
          name: name,
          before: before,
          destination: destinationURL,
          state: &state)
      default:
        throw InstrumentsConversionError.sourceRejected
      }
    }
    var directoryAfter = stat()
    guard fstat(directoryDescriptor, &directoryAfter) == 0,
      stable(directoryBefore, directoryAfter)
    else { throw InstrumentsConversionError.sourceChanged }
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
    guard sourceDescriptor >= 0 else { throw InstrumentsConversionError.sourceRejected }
    defer { close(sourceDescriptor) }
    var opened = stat()
    guard fstat(sourceDescriptor, &opened) == 0, (opened.st_mode & S_IFMT) == S_IFREG,
      opened.st_size >= 0, stable(before, opened)
    else { throw InstrumentsConversionError.sourceChanged }
    let size = UInt64(opened.st_size)
    let (nextTotal, overflow) = state.totalBytes.addingReportingOverflow(size)
    guard !overflow, nextTotal <= maximumBytes else {
      throw InstrumentsConversionError.sourceTooLarge
    }
    state.totalBytes = nextTotal
    let outputDescriptor = open(
      destination.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard outputDescriptor >= 0 else { throw InstrumentsConversionError.sourceRejected }
    defer { close(outputDescriptor) }
    let input = FileHandle(fileDescriptor: sourceDescriptor, closeOnDealloc: false)
    let output = FileHandle(fileDescriptor: outputDescriptor, closeOnDealloc: false)
    var copied: UInt64 = 0
    while let chunk = try input.read(upToCount: 1024 * 1024), !chunk.isEmpty {
      copied += UInt64(chunk.count)
      guard copied <= size else { throw InstrumentsConversionError.sourceRejected }
      try output.write(contentsOf: chunk)
    }
    var after = stat()
    guard copied == size, fstat(sourceDescriptor, &after) == 0, stable(opened, after) else {
      throw InstrumentsConversionError.sourceChanged
    }
    try output.synchronize()
  }

  private static func valid(relative: String) -> Bool {
    !relative.isEmpty && relative.utf8.count <= maximumPathBytes
      && !relative.split(separator: "/").contains("..")
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

  private static func updateLengthPrefixed(_ data: Data, digest: inout SHA256) {
    let length = UInt64(data.count).bigEndian
    digest.update(data: withUnsafeBytes(of: length) { Data($0) })
    digest.update(data: data)
  }
}
