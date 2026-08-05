import Foundation

struct BrowserAdapterFileService: Sendable {
  static let manifestRelativePath =
    "Library/Application Support/Google/Chrome/NativeMessagingHosts/com.glassbox.browser.json"
  static let inboxRelativePath =
    "Library/Application Support/Glassbox Browser Adapter/Inbox"

  let home: URL

  init(home: URL = FileManager.default.homeDirectoryForCurrentUser) { self.home = home }

  var inboxURL: URL { home.appendingPathComponent(Self.inboxRelativePath, isDirectory: true) }
  var manifestURL: URL { home.appendingPathComponent(Self.manifestRelativePath) }

  func items() throws -> [BrowserEvidenceItem] {
    guard FileManager.default.fileExists(atPath: inboxURL.path) else { return [] }
    let keys: Set<URLResourceKey> = [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey]
    return try FileManager.default.contentsOfDirectory(
      at: inboxURL, includingPropertiesForKeys: Array(keys),
      options: [.skipsHiddenFiles, .skipsPackageDescendants])
      .compactMap { url in
        guard url.pathExtension == "glassbox", !url.lastPathComponent.hasPrefix(".") else {
          return nil
        }
        let values = try url.resourceValues(forKeys: keys)
        guard values.isRegularFile == true else { return nil }
        return BrowserEvidenceItem(
          url: url, bytes: Int64(values.fileSize ?? 0),
          modified: values.contentModificationDate ?? .distantPast)
      }
      .sorted { $0.modified > $1.modified }
  }

  func installManifest(hostURL: URL) throws {
    guard hostURL.isFileURL, hostURL.path.hasPrefix("/"),
      FileManager.default.isExecutableFile(atPath: hostURL.path)
    else { throw BrowserAdapterFileError.invalidHost }
    let manifest = NativeHostManifest.production(hostPath: hostURL.path)
    let data = try JSONEncoder.sorted.encode(manifest)
    let directory = manifestURL.deletingLastPathComponent()
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    let temporary = directory.appendingPathComponent(".com.glassbox.browser.(UUID().uuidString).tmp")
    guard FileManager.default.createFile(
      atPath: temporary.path, contents: data,
      attributes: [.posixPermissions: 0o600])
    else { throw BrowserAdapterFileError.writeFailed }
    do {
      if FileManager.default.fileExists(atPath: manifestURL.path) {
        let existing = try Data(contentsOf: manifestURL)
        guard (try? JSONDecoder().decode(NativeHostManifest.self, from: existing)).map({ $0.name })
          == "com.glassbox.browser"
        else { throw BrowserAdapterFileError.foreignManifest }
        try FileManager.default.removeItem(at: manifestURL)
      }
      try FileManager.default.moveItem(at: temporary, to: manifestURL)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
    } catch {
      try? FileManager.default.removeItem(at: temporary)
      throw error
    }
  }

  func resetManifest() throws {
    guard FileManager.default.fileExists(atPath: manifestURL.path) else { return }
    let data = try Data(contentsOf: manifestURL)
    guard let manifest = try? JSONDecoder().decode(NativeHostManifest.self, from: data),
      manifest.name == "com.glassbox.browser"
    else { throw BrowserAdapterFileError.foreignManifest }
    try FileManager.default.removeItem(at: manifestURL)
  }

  func export(item: BrowserEvidenceItem, to destination: URL) throws {
    guard item.url.deletingLastPathComponent().standardizedFileURL == inboxURL.standardizedFileURL,
      item.url.pathExtension == "glassbox",
      !FileManager.default.fileExists(atPath: destination.path)
    else { throw BrowserAdapterFileError.invalidExport }
    try FileManager.default.copyItem(at: item.url, to: destination)
  }

  func deleteOwned(item: BrowserEvidenceItem) throws {
    guard item.url.deletingLastPathComponent().standardizedFileURL == inboxURL.standardizedFileURL,
      item.url.pathExtension == "glassbox"
    else { throw BrowserAdapterFileError.invalidExport }
    try FileManager.default.removeItem(at: item.url)
  }
}

private extension JSONEncoder {
  static var sorted: JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    return encoder
  }
}

enum BrowserAdapterFileError: LocalizedError {
  case invalidHost, writeFailed, foreignManifest, invalidExport

  var errorDescription: String? {
    switch self {
    case .invalidHost: "The signed Native Messaging host is missing or invalid."
    case .writeFailed: "The Native Messaging manifest could not be written safely."
    case .foreignManifest: "An unrecognized manifest occupies the Glassbox host location."
    case .invalidExport: "The selected evidence cannot be exported to that destination."
    }
  }
}
