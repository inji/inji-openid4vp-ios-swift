import XCTest
@testable import OpenID4VP

final class CredentialUtilsTests: XCTestCase {

    private let classNameValue = "CredentialUtilsTests"

    private let sdHashes = [
        "C2P_qoq0PvTo1YYrv3_5FWi4iEaZUGKYaCkzakgMIHc",
        "F4ZdBPIx0rQbhnidnSp1HL7-TR_OCFqhWIVJZ7mB3FU",
        "Utv-tGhIgoKIKNTb9gtbr7bY9EmQAMKNwtXjcMsQpLM",
        "gw_Fj-4LQFJCgrdUJpEBmm4nza31XRtag5Sh_EP8DzU",
        "kat4UAmK9xnNGz5-xEvCTufenAG9RuEoxykrK-lNKeg",
        "oEBLKW4QD9gcJnHBF-XGeklA3x8L15ulCw5UqpeyhIs",
        "qtiUJzlSL9M2n7yxghkINJxUJt6KfZdPcDkqhtVq4zQ",
        "y4Lyr2z6AIdHhp8et5Vq9rhSb65sGiMX06EVZ1-_i6Q"
    ]
    private let cnfKid = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii1pa2lOemRxV1BDMWlYSW9KNDJvV0M4cU16VHdvWjA4ejY5RjVZZWNaOWsiLCJ5IjoiUUlQcGRPREx4X1hxdVhLaUZhV3oyWW84MmRWelUzNWpFSjRNc2NVR0Z5OCIsInVzZSI6InNpZyJ9#0"

    private var jwtBodyClaims: [String: Any] {
        [
            "issuance_date": "2025-08-18",
            "expiry_date": "2026-08-28",
            "issuing_country": "DE",
            "nbf": 1755475200,
            "exp": 1787875200,
            "vct": "https://example.eudi.ec.europa.eu/cor/1",
            "iss": "https://funke.animo.id",
            "iat": 1756896653,
            "_sd_alg": "sha-256",
            "_sd": sdHashes,
            "family_name": "Doe",
            "given_name": "John"
        ]
    }

    private func assertPayloadEqual(_ actual: [String: Any], _ expected: [String: Any], file: StaticString = #file, line: UInt = #line) {
        XCTAssertEqual(NSDictionary(dictionary: actual), NSDictionary(dictionary: expected), file: file, line: line)
    }

    // MARK: - extractSdJwtPayload

    func testExtractSdJwtPayloadReturnsCredentialAndPayload() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let (rawCredential, payload, _) = try extractSdJwtPayload(credential, className: classNameValue)

        let expectedJwtBodyClaims: [String: Any] = [
            "issuance_date": "2025-08-18",
            "expiry_date": "2026-08-28",
            "issuing_country": "DE",
            "nbf": 1755475200,
            "exp": 1787875200,
            "vct": "https://example.eudi.ec.europa.eu/cor/1",
            "iss": "https://funke.animo.id",
            "iat": 1756896653,
            "_sd_alg": "sha-256"
        ]
        XCTAssertEqual(rawCredential, sampeVcSdJwtWithHolderBinding)
        for (key, expected) in expectedJwtBodyClaims {
            XCTAssertEqual("\(payload[key] ?? "nil")", "\(expected)", "Mismatch for key '\(key)'")
        }
        XCTAssertNil(payload["family_name"])
        XCTAssertNil(payload["given_name"])
    }

    func testExtractSdJwtPayloadThrowsWhenCredentialIsNotString() throws {
        let credential = AnyCodable(["key": "value"])

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSdJwtPayloadThrowsWhenStringIsEmpty() throws {
        let credential = AnyCodable("")

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is malformed or empty", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSdJwtPayloadThrowsWhenJwtIsInvalid() throws {
        let credential = AnyCodable("not.a.valid~jwt")

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: classNameValue))
    }

    func testExtractSdJwtPayloadWithoutDecodeDisclosuresOmitsSelectiveClaims() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let (_, payload, _) = try extractSdJwtPayload(credential, className: classNameValue)

        var expectedPayload = jwtBodyClaims
        expectedPayload["cnf"] = ["kid": cnfKid]
        assertPayloadEqual(payload, expectedPayload)
    }

    func testExtractSdJwtPayloadWithDecodeDisclosuresMergesSelectiveClaims() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let (_, payload, _) = try extractSdJwtPayload(credential, className: classNameValue, decodeDisclosures: true)

        var expectedPayload = jwtBodyClaims
        expectedPayload["cnf"] = ["kid": cnfKid]

        assertPayloadEqual(payload, expectedPayload)
    }

    func testExtractSdJwtPayloadDecodeDisclosuresSkipsMalformedSegments() throws {
        let parts = sampeVcSdJwtWithHolderBinding.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard parts.count > 2 else {
            XCTFail("fixture must include disclosures")
            return
        }
        var mutated = parts
        mutated[1] = "!!!not-valid!!!"
        let credential = AnyCodable(mutated.joined(separator: "~"))

        let (_, payload, _) = try extractSdJwtPayload(credential, className: classNameValue, decodeDisclosures: true)

        // First disclosure is malformed and skipped; remaining valid ones are still decoded.
        // JWT body claims must still be intact.
        XCTAssertEqual(payload["vct"] as? String, "https://example.eudi.ec.europa.eu/cor/1")
        XCTAssertEqual(payload["iss"] as? String, "https://funke.animo.id")
        XCTAssertNil(payload["family_name"], "Malformed first disclosure must be skipped — family_name must be absent")
    }
    
    func testExtractSdJwtPayloadWithNestedDisclosableClaims() throws {
        let testSdJwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg~WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ~WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0~"
        
        let (_, _, fullyResolvedClaims) = try extractSdJwtPayload(AnyCodable(testSdJwt), className: classNameValue)
        
        let expectedResolvedClaims: [String: Any] = [
            "vct": "IdentityCredential",
            "family_name": "Doe",
            "phone_number": "+1-202-555-0101",
            "address": [
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "Anystate",
                "country": "US"
            ],
            "cnf": [
                "jwk": [
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
                ]
            ],
            "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
            "iat": 1698151532,
            "is_over_18": true,
            "is_over_21": true,
            "given_name": "John",
            "birthdate": "1940-01-01",
            "email": "johndoe@example.com",
            "is_over_65": true
        ]

        assertDictionariesEqual(expected: expectedResolvedClaims, actual: fullyResolvedClaims)
    }

    func testExtractSdJwtPayloadWorksWithNoHolderBinding() throws {
        let credential = AnyCodable(sampleVcSdJwtWithNoHolderBinding)

        let (rawCredential, payload, _) = try extractSdJwtPayload(credential, className: classNameValue)

        XCTAssertEqual(rawCredential, sampleVcSdJwtWithNoHolderBinding)
        assertPayloadEqual(payload, jwtBodyClaims)
    }

    // MARK: - extractSDJwtString

    func testExtractSDJwtStringReturnsStringValue() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let result = try extractSDJwtString(from: credential, className: classNameValue)

        XCTAssertEqual(result, sampeVcSdJwtWithHolderBinding)
    }

    func testExtractSDJwtStringThrowsWhenValueIsNotString() throws {
        let credential = AnyCodable(42)

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSDJwtStringThrowsWhenValueIsArray() throws {
        let credential = AnyCodable(["a", "b"])

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSDJwtStringThrowsWhenValueIsDictionary() throws {
        let credential = AnyCodable(["key": "value"])

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
}

