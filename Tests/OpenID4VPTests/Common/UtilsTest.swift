import Foundation
import XCTest
@testable import OpenID4VP

struct MockDataClass: Codable {
    let key: String
    let keyWithMoreThanOneWord: String
    let nullableField: String?
    let number: Int
    
    enum CodingKeys: String, CodingKey {
        case key
        case keyWithMoreThanOneWord = "key_with_more_than_one_word"
        case nullableField = "nullable_field"
        case number
    }
}

class UtilsTest : XCTestCase {
    private let testClassName = String(describing: UtilsTest.self)
    
    /// Validate url tests
    
    func testInvalidUrl() {
        let testCases: [TestCase] = [
            TestCase(input: "www.example.com"),
            TestCase(input: "http://example.com/space here"),
            TestCase(input: "http://"),
            TestCase(input: "https://example"),
            TestCase(input: "http://example.com/file%/name"),
            TestCase(input: "http://example.com:99999"),
            TestCase(input: "http:///example.com"),
            TestCase(input: "http://example.com/search?q=hello%20world#@fragment"),
            TestCase(input: "http://:8080"),
            TestCase(input: ""),
            TestCase(input: "https://example.com/invalid|character")
        ]
        
        for testCase in testCases {
            XCTAssertFalse(isValidUri(testCase.input))
        }
    }
    
    func testValidUrl(){
        XCTAssertTrue(isValidUri("https://example.com"))
    }
    
    /// Check if input is JWT tests
    
    func testIsStringIsJWT() {
        let invalidJwt = isJWS("eeeee")
        let validJwt = isJWS("ec.exx.ef")
        
        XCTAssertFalse(invalidJwt)
        XCTAssertTrue(validJwt)
    }
    
    /// Test for string to HTTP method conversion
    
    func testDetermineHttpMethodToReturnHttpMethodIfInputIsValid(){
        let getMethod1 = try? determineHttpMethod(method: "get")
        let getMethod2 = try? determineHttpMethod(method: "GET")
        let getMethod3 = try? determineHttpMethod(method: "Get")
        let postMethod1 = try? determineHttpMethod(method: "post")
        let postMethod2 = try? determineHttpMethod(method: "POST")
        let postMethod3 = try? determineHttpMethod(method: "Post")
        
        XCTAssertEqual(getMethod1, .get)
        XCTAssertEqual(getMethod2, .get)
        XCTAssertEqual(getMethod3, .get)
        XCTAssertEqual(postMethod1, .post)
        XCTAssertEqual(postMethod2, .post)
        XCTAssertEqual(postMethod3, .post)
    }
    
    func testDetermineHttpMethodToThrowErrorIfInputIsNotValid(){
        XCTAssertThrowsError(try determineHttpMethod(method: "head")) { error in
            XCTAssertEqual(AuthorizationRequestException.unsupportedHttpMethod(message: "head"), error as! AuthorizationRequestException)
            XCTAssertEqual("Unsupported HTTP method: head", error.localizedDescription)
        }
    }
    
    /// Test for dictionary of [String: Any] to data conversion
    
    func testToDataConversionSuccess() throws {
        
        let mockEncodable = MockDataClass(key: "value", keyWithMoreThanOneWord: "value1", nullableField: "value3", number: 1)
        
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
        XCTAssertEqual(encodedMock?["key"] as? String, "value")
        XCTAssertEqual(encodedMock?["key_with_more_than_one_word"] as? String, "value1")
        XCTAssertEqual(encodedMock?["nullable_field"] as? String, "value3")
        XCTAssertEqual(encodedMock?["number"] as? Int, 1)
    }
    
    func testToDataConversionFailure() throws {
        let input: [String: Any] = ["timestamp": Date()]
        
        XCTAssertThrowsError(try toData(input), "Expected error for invalid JSON input") { error in
            XCTAssertEqual("Json Encoding failed for  due to this error: Invalid JSON object.", error.localizedDescription)
        }
    }
    
    /// Encoding of classes to JSON test

    struct MockFailingEncodable: Encodable {
        func encode(to encoder: Encoder) throws {
            throw NSError(domain: "EncodingError", code: 0, userInfo: nil)
        }
    }
    
    func testEncodeWithAllProperties() throws {
        let mockDataClass = MockDataClass(
            key: "id_credential",
            keyWithMoreThanOneWord: "ldp_vp",
            nullableField: "value",
            number: 1
        )

        let encodedJson = try encode(mockDataClass, fieldName: "mockDataClass", className: testClassName)
        let expectedJson = "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\",\"nullable_field\":\"value\",\"number\":1}"
        
        assertJsonString(expected: expectedJson, actual: encodedJson)
    }

    func testEncodeWithoutNullableField() throws {
        let mockDataClass = MockDataClass(
            key: "id_credential",
            keyWithMoreThanOneWord: "ldp_vp",
            nullableField: nil,
            number: 1
        )

        let encodedJson = try encode(mockDataClass, fieldName: "mockDataClass", className: testClassName)
        let expectedJson = "{\"key\":\"id_credential\",\"number\":1,\"key_with_more_than_one_word\":\"ldp_vp\"}"
        
        assertJsonString(expected: expectedJson, actual: encodedJson)
    }

    
    func testEncodeFailure() {
        
        let failingObject = MockFailingEncodable()
        
        XCTAssertThrowsError(try encode(failingObject, fieldName: "failingObject", className: testClassName)) {error in
            XCTAssertEqual(error.localizedDescription, "Json Encoding failed for failingObject due to this error: The operation couldn’t be completed. (EncodingError error 0.).")
        }
    }
}
