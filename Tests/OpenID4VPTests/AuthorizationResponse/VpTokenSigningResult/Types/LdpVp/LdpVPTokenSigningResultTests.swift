import XCTest
@testable import OpenID4VP

final class LdpVPTokenSigningResultTests: XCTestCase {
    
    // MARK: - JsonWebSignature2020 signature suite (jws)
    
    func testValidateSuccess() throws {
        let validMetadata = ldpVPTokenSigningResult
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testValidateFailureEmptyString() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: "", proofValue: "valid-proof",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testValidateFailureNullValue() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: nil, proofValue: "test",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // MARK: - Ed25519Signature2020 (proofValue)

    func testValidateSuccessForEd25519Signature2020WithValidProofValue() {
        let result = LdpVPTokenSigningResult(
            jws: nil,
            proofValue: "valid-proof-value",
            signatureAlgorithm: SignatureAlgorithm.ed25519Signature2020.rawValue
        )
        XCTAssertNoThrow(try result.validate())
    }

    func testValidateFailureForEd25519Signature2020WithEmptyProofValue() {
        let result = LdpVPTokenSigningResult(
            jws: nil,
            proofValue: "",
            signatureAlgorithm: SignatureAlgorithm.ed25519Signature2020.rawValue
        )
        XCTAssertThrowsError(try result.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->proofValue value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testValidateFailureForEd25519Signature2020WithNilProofValue() {
        let result = LdpVPTokenSigningResult(
            jws: nil,
            proofValue: nil,
            signatureAlgorithm: SignatureAlgorithm.ed25519Signature2020.rawValue
        )
        XCTAssertThrowsError(try result.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->proofValue value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - RsaSignature2018 (jws branch)

    func testValidateSuccessForRsaSignature2018WithValidJws() {
        let result = LdpVPTokenSigningResult(
            jws: "valid-jws",
            proofValue: nil,
            signatureAlgorithm: SignatureAlgorithm.rsaSignature2018.rawValue
        )
        XCTAssertNoThrow(try result.validate())
    }

    func testValidateFailureForRsaSignature2018WithEmptyJws() {
        let result = LdpVPTokenSigningResult(
            jws: "",
            proofValue: nil,
            signatureAlgorithm: SignatureAlgorithm.rsaSignature2018.rawValue
        )
        XCTAssertThrowsError(try result.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testValidateFailureForRsaSignature2018WithNilJws() {
        let result = LdpVPTokenSigningResult(
            jws: nil,
            proofValue: nil,
            signatureAlgorithm: SignatureAlgorithm.rsaSignature2018.rawValue
        )
        XCTAssertThrowsError(try result.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Ed25519Signature2018 (jws branch)

    func testValidateSuccessForEd25519Signature2018WithValidJws() {
        let result = LdpVPTokenSigningResult(
            jws: "valid-jws",
            proofValue: nil,
            signatureAlgorithm: SignatureAlgorithm.ed25519Signature2018.rawValue
        )
        XCTAssertNoThrow(try result.validate())
    }

    func testValidateFailureForEd25519Signature2018WithEmptyJws() {
        let result = LdpVPTokenSigningResult(
            jws: "",
            proofValue: nil,
            signatureAlgorithm: SignatureAlgorithm.ed25519Signature2018.rawValue
        )
        XCTAssertThrowsError(try result.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Unsupported algorithm 

    func testValidateFailureForUnsupportedAlgorithm() {
        let result = LdpVPTokenSigningResult(
            jws: "valid-jws",
            proofValue: "valid-proof",
            signatureAlgorithm: "UnsupportedAlgorithm"
        )
        XCTAssertThrowsError(try result.validate()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Unsupported algorithm: UnsupportedAlgorithm",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
