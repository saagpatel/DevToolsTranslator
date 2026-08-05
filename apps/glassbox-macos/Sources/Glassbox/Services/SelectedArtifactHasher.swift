import CryptoKit
import Darwin
import Foundation

enum SelectedArtifactHashError: Error, Equatable {
  case invalidRoot
  case tooManyFiles
  case artifactTooLarge
  case invalidRelativePath
  case unsupportedFileType
  case changedDuringRead
}

enum SelectedArtifactHasher {
  static let maximumFiles = 100_000
  static let maximumBytes: UInt64 = 64 * 1024 * 1024 * 1024
  static let maximumRelativePathBytes = 4_096
  private static let chunkBytes = 1024 * 1024

  struct HashedRegularFile: @unchecked Sendable {
    let handle: FileHandle
    let sha256: String
    let size: UInt64
  }

  static func openAndHash(file: URL, maximumBytes: UInt64) throws -> HashedRegularFile {
    let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    guard values.isRegularFile == true, values.isSymbolicLink != true else {
      throw SelectedArtifactHashError.unsupportedFileType
    }
    let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw SelectedArtifactHashError.unsupportedFileType }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_size >= 0
    else {
      close(descriptor)
      throw SelectedArtifactHashError.unsupportedFileType
    }
    let size = UInt64(metadata.st_size)
    guard size <= maximumBytes else {
      close(descriptor)
      throw SelectedArtifactHashError.artifactTooLarge
    }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    do {
      var digest = SHA256()
      var readBytes: UInt64 = 0
      while let chunk = try handle.read(upToCount: chunkBytes), !chunk.isEmpty {
        readBytes += UInt64(chunk.count)
        guard readBytes <= size else { throw SelectedArtifactHashError.changedDuringRead }
        digest.update(data: chunk)
      }
      guard readBytes == size else { throw SelectedArtifactHashError.changedDuringRead }
      var after = stat()
      guard fstat(descriptor, &after) == 0, stable(metadata, after)
      else { throw SelectedArtifactHashError.changedDuringRead }
      try handle.seek(toOffset: 0)
      return HashedRegularFile(
        handle: handle,
        sha256: digest.finalize().map { String(format: "%02x", $0) }.joined(),
        size: size)
    } catch {
      try? handle.close()
      throw error
    }
  }

  static func sha256(directory root: URL) throws -> String {
    let rootValues = try root.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
    guard rootValues.isDirectory == true, rootValues.isSymbolicLink != true else {
      throw SelectedArtifactHashError.invalidRoot
    }
    let canonicalRoot = root.resolvingSymlinksInPath().standardizedFileURL
    let prefix = canonicalRoot.path + "/"
    var enumerationFailed = false
    guard
      let enumerator = FileManager.default.enumerator(
        at: canonicalRoot,
        includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
        options: [],
        errorHandler: { _, _ in
          enumerationFailed = true
          return false
        })
    else { throw SelectedArtifactHashError.invalidRoot }
    var files: [(relative: String, url: URL)] = []
    for case let url as URL in enumerator {
      let values = try url.resourceValues(forKeys: [
        .isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey,
      ])
      if values.isSymbolicLink == true {
        throw SelectedArtifactHashError.unsupportedFileType
      }
      if values.isDirectory == true { continue }
      guard values.isRegularFile == true else {
        throw SelectedArtifactHashError.unsupportedFileType
      }
      guard files.count < maximumFiles else { throw SelectedArtifactHashError.tooManyFiles }
      let canonicalURL = url.resolvingSymlinksInPath().standardizedFileURL
      guard canonicalURL.path.hasPrefix(prefix) else {
        throw SelectedArtifactHashError.invalidRelativePath
      }
      let relative = String(canonicalURL.path.dropFirst(prefix.count))
      guard !relative.isEmpty, relative.utf8.count <= maximumRelativePathBytes,
        !relative.split(separator: "/").contains("..")
      else { throw SelectedArtifactHashError.invalidRelativePath }
      files.append((relative, canonicalURL))
    }
    guard !enumerationFailed else { throw SelectedArtifactHashError.invalidRoot }
    files.sort { $0.relative.utf8.lexicographicallyPrecedes($1.relative.utf8) }

    var digest = SHA256()
    digest.update(data: Data("glassbox-selected-directory-v1\0".utf8))
    var totalBytes: UInt64 = 0
    for file in files {
      let descriptor = open(file.url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
      guard descriptor >= 0 else { throw SelectedArtifactHashError.unsupportedFileType }
      defer { close(descriptor) }
      var metadata = stat()
      guard fstat(descriptor, &metadata) == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
        metadata.st_size >= 0
      else { throw SelectedArtifactHashError.unsupportedFileType }
      let size = UInt64(metadata.st_size)
      let (nextTotal, overflow) = totalBytes.addingReportingOverflow(size)
      guard !overflow, nextTotal <= maximumBytes else {
        throw SelectedArtifactHashError.artifactTooLarge
      }
      totalBytes = nextTotal
      updateLengthPrefixed(Data(file.relative.utf8), digest: &digest)
      digest.update(data: withUnsafeBytes(of: size.bigEndian) { Data($0) })
      let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
      var readBytes: UInt64 = 0
      while let chunk = try handle.read(upToCount: chunkBytes), !chunk.isEmpty {
        readBytes += UInt64(chunk.count)
        guard readBytes <= size else { throw SelectedArtifactHashError.changedDuringRead }
        digest.update(data: chunk)
      }
      var after = stat()
      guard readBytes == size, fstat(descriptor, &after) == 0, stable(metadata, after) else {
        throw SelectedArtifactHashError.changedDuringRead
      }
    }
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
  }

  private static func updateLengthPrefixed(_ data: Data, digest: inout SHA256) {
    let length = UInt64(data.count).bigEndian
    digest.update(data: withUnsafeBytes(of: length) { Data($0) })
    digest.update(data: data)
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
}
