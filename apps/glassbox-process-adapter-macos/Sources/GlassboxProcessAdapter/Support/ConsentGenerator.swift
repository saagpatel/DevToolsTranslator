import Foundation
import Security

enum ProcessConsentGenerator {
  static func makeHex() throws -> String {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
      throw ProcessConsentError.randomFailure
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
  }
}

enum ProcessConsentError: LocalizedError {
  case randomFailure
  var errorDescription: String? { "A one-shot capture capability could not be generated." }
}
