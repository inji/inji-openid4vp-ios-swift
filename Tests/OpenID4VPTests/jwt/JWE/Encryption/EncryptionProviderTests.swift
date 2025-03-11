import XCTest
@testable import OpenID4VP

final class EncryptionProviderTests: XCTestCase {
    func testGetEncryptorSuccess() throws {
        let encryption = try EncryptionProvider.getEncryptor("A256GCM")

        XCTAssertTrue(encryption is AESGCMEncryption)

    }

    func testGetEncryptorFailureUnsupportedAlgorithm() throws {
        XCTAssertThrowsError(try EncryptionProvider.getEncryptor("UNSUPPORTED")) { error in
            XCTAssertEqual(error.localizedDescription, "Required Encryption algorithm is not supported.")
        }
    }
}
