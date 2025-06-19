import XCTest
@testable import OpenID4VP

final class JWKSTests: XCTestCase {

    func testThrowErrorWhenValidationOfJWKFails() {
        let json = """
        {
          "kty": "EC",
          "use": "",
          "crv": "P-256",
          "x": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "alg": "ES256",
          "kid": "1"
        }
        """.data(using: .utf8)!

        let jwk = try! JSONDecoder().decode(JWK.self, from: json)
        let jwks = JWKS(keys: [jwk])

        XCTAssertThrowsError(try jwks.validate()) { error in
            XCTAssertNotNil(error as? Exceptions)
            XCTAssertTrue(error.localizedDescription.contains("jwks.keys[0]"))
        }
    }

    func testValidateSucceedsWithValidJWK() {
        let json = """
        {
          "kty": "EC",
          "use": "sig",
          "crv": "P-256",
          "x": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "alg": "ES256",
          "kid": "1"
        }
        """.data(using: .utf8)!

        let jwk = try! JSONDecoder().decode(JWK.self, from: json)
        let jwks = JWKS(keys: [jwk])

        XCTAssertNoThrow(try jwks.validate())
    }

    func testMultipleJWKsWithFirstInvalid() {
        let invalidJson = """
        {
          "kty": "EC",
          "use": "",
          "crv": "P-256",
          "x": "abc",
          "alg": "ES256",
          "kid": "key-1"
        }
        """.data(using: .utf8)!

        let validJson = """
        {
          "kty": "EC",
          "use": "sig",
          "crv": "P-256",
          "x": "validX",
          "alg": "ES256",
          "kid": "key-2"
        }
        """.data(using: .utf8)!

        let jwks = JWKS(keys: [
            try! JSONDecoder().decode(JWK.self, from: invalidJson),
            try! JSONDecoder().decode(JWK.self, from: validJson)
        ])

        XCTAssertThrowsError(try jwks.validate()) { error in
            XCTAssertTrue(error.localizedDescription.contains("jwks.keys[0]"))
        }
    }

    func testMultipleJWKsWithSecondInvalid() {
        let validJson = """
        {
          "kty": "EC",
          "use": "sig",
          "crv": "P-256",
          "x": "validX",
          "alg": "ES256",
          "kid": "key-1"
        }
        """.data(using: .utf8)!

        let invalidJson = """
        {
          "kty": "",
          "use": "sig",
          "crv": "P-256",
          "x": "xyz",
          "alg": "ES256",
          "kid": "key-2"
        }
        """.data(using: .utf8)!

        let jwks = JWKS(keys: [
            try! JSONDecoder().decode(JWK.self, from: validJson),
            try! JSONDecoder().decode(JWK.self, from: invalidJson)
        ])
    
        XCTAssertThrowsError(try jwks.validate()) { error in
            XCTAssertTrue(error.localizedDescription.contains("jwks.keys[1]"))
        }
    }
}
