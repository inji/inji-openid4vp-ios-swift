import Foundation
@testable import OpenID4VP

final class MockNonceProvider: NonceProvider {
    override func generateNonce(entropy: Int = 16) -> String {
        return "mock-nonce"
    }
}
