import Foundation

protocol PublicKeyResolver {
    // TODO: should return publicKey instead of String once multiple signature support is added
    func resolveKey(header: [String: Any])async throws -> String
}
