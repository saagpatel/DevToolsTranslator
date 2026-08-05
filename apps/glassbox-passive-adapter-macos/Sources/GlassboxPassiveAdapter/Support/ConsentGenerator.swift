import Foundation
import Security

enum ConsentGenerator {
  static func makeHex() throws -> String {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
      throw ConsentGeneratorError.randomFailure
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
  }
}

enum ConsentGeneratorError: LocalizedError {
  case randomFailure

  var errorDescription: String? { "A one-shot consent capability could not be generated." }
}
