//
//  JWKTests.swift
//  
//
//  Created by Kiruthika Jeyashankar on 11/03/25.
//

import XCTest
@testable import OpenID4VP

final class JWKSTests: XCTestCase {
    func testThrowErrorWhenValidationOfJWKFails() {
        let jwksWithInvalidJWK = JWKS(keys: [JWK(kty: "EC", use: "", crv: "P-256", x: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", alg: "ES256", kid: "1")])
        
        XCTAssertThrowsError(try jwksWithInvalidJWK.validate()){ error in
            XCTAssertEqual("jwks.keys[0] is invalid", error.localizedDescription)
        }
        
    }
}
