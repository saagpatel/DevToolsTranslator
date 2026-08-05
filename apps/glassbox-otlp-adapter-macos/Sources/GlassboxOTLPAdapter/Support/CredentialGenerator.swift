import Foundation
import Security

enum CredentialGenerator {
  static func makeHex(byteCount: Int = 32) throws -> String {
    precondition(byteCount > 0)
    var bytes = [UInt8](repeating: 0, count: byteCount)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
      throw CredentialError.randomGenerationFailed
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
  }
}

enum CredentialError: LocalizedError {
  case randomGenerationFailed

  var errorDescription: String? {
    "A secure one-use attachment credential could not be generated."
  }
}
