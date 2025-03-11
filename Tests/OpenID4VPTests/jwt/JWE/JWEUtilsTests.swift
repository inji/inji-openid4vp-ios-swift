import XCTest
import CryptoKit

@testable import OpenID4VP

final class JWEUtilsTests: XCTestCase {
    
    func testGetPayloadDataSuccess() throws {
        
        let mockEncodable = MockEncodable(name: "John Doe", age: 30)
        
        let bodyParams: [String: Any] = [
            "key1": "value1",
            "key2": 123,
            "key3": mockEncodable
        ]
        
        let payloadData = try toData(bodyParams)
        
        let decoded = try JSONSerialization.jsonObject(with: payloadData, options: []) as? [String: Any]
        
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?["key1"] as? String, "value1")
        XCTAssertEqual(decoded?["key2"] as? Int, 123)
        
        let encodedMock = decoded?["key3"] as? [String: Any]
        XCTAssertNotNil(encodedMock)
        XCTAssertEqual(encodedMock?["name"] as? String, "John Doe")
        XCTAssertEqual(encodedMock?["age"] as? Int, 30)
    }
    
    func testEncodeJWEComponents() throws {
           
           let header: [String: Any] = ["alg": "ECDH-ES", "enc": "A256GCM"]
           let encryptedKey = "mockEncryptedKey"
           let nonce = Data([0x01, 0x02, 0x03, 0x04, 0x05])
           let ciphertext = Data([0xAA, 0xBB, 0xCC, 0xDD])
           let tag = Data([0x11, 0x22, 0x33, 0x44])
           
           let encodedJWE = try encodeJWEComponents(
               header: header,
               encryptedKey: encryptedKey,
               nonce: nonce,
               ciphertext: ciphertext,
               tag: tag
           )

           let components = encodedJWE.split(separator: ".")
           XCTAssertEqual(components.count, 5, "JWE should have 5 components")

           let expectedHeaderJson = try JSONSerialization.data(withJSONObject: header)
           let expectedEncodedHeader = base64URLEscaped(expectedHeaderJson.base64EncodedString())
           XCTAssertEqual(String(components[0]), expectedEncodedHeader, "Header encoding is incorrect")

           XCTAssertEqual(String(components[1]), encryptedKey, "Encrypted key should match the input")

           XCTAssertEqual(String(components[2]), base64URLEscaped(nonce.base64EncodedString()), "Nonce encoding is incorrect")
           XCTAssertEqual(String(components[3]), base64URLEscaped(ciphertext.base64EncodedString()), "Ciphertext encoding is incorrect")
           XCTAssertEqual(String(components[4]), base64URLEscaped(tag.base64EncodedString()), "Auth tag encoding is incorrect")
       }
}
