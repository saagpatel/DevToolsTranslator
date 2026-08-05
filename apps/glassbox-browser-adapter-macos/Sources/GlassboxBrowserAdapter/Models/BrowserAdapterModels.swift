import Foundation

struct BrowserEvidenceItem: Identifiable, Equatable, Sendable {
  let url: URL
  let bytes: Int64
  let modified: Date
  var id: String { url.lastPathComponent }
}

struct NativeHostManifest: Codable, Equatable, Sendable {
  let name: String
  let description: String
  let path: String
  let type: String
  let allowedOrigins: [String]

  enum CodingKeys: String, CodingKey {
    case name, description, path, type
    case allowedOrigins = "allowed_origins"
  }

  static func production(hostPath: String) -> NativeHostManifest {
    NativeHostManifest(
      name: "com.glassbox.browser",
      description: "Glassbox selected-tab evidence broker",
      path: hostPath,
      type: "stdio",
      allowedOrigins: ["chrome-extension://giffhfldblangaphoeeeelcapcmedjbd/"])
  }
}

enum BrowserAdapterStatus: Equatable {
  case ready(String)
  case failed(String)

  var message: String {
    switch self {
    case .ready(let message), .failed(let message): message
    }
  }
}
