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
}
