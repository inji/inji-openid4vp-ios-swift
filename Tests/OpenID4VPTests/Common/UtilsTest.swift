import Foundation
import XCTest
@testable import OpenID4VP

class UtilsTest : XCTestCase {
    struct TestCase {
        let input: String
    }
    
    // Validate url tests
    
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
    
    // Check if input is JWT tests
    
    func testIsStringIsJWT() {
        let invalidJwt = isJWT("eeeee")
        let validJwt = isJWT("ec.exx.ef")
        
        XCTAssertFalse(invalidJwt)
        XCTAssertTrue(validJwt)
    }
    
    // Test for string to HTTP method conversion
    
    func testDetermineHttpMethodToReturnHttpMethodIfInputIsValid(){
        let getMethod1 = try? determineHttpMethod(method: "get")
        let getMethod2 = try? determineHttpMethod(method: "GET")
        let getMethod3 = try? determineHttpMethod(method: "Get")
        let postMethod1 = try? determineHttpMethod(method: "post")
        let postMethod2 = try? determineHttpMethod(method: "POST")
        let postMethod3 = try? determineHttpMethod(method: "Post")
        
        XCTAssertEqual(getMethod1, HTTP_METHOD.GET)
        XCTAssertEqual(getMethod2, HTTP_METHOD.GET)
        XCTAssertEqual(getMethod3, HTTP_METHOD.GET)
        XCTAssertEqual(postMethod1, HTTP_METHOD.POST)
        XCTAssertEqual(postMethod2, HTTP_METHOD.POST)
        XCTAssertEqual(postMethod3, HTTP_METHOD.POST)
    }
    
    func testDetermineHttpMethodToThrowErrorIfInputIsNotValid(){
        XCTAssertThrowsError(try determineHttpMethod(method: "head")) { error in
            XCTAssertEqual(AuthorizationRequestException.unsupportedHttpMethod(message: "head"), error as! AuthorizationRequestException)
            XCTAssertEqual("Unsupported HTTP method: head", error.localizedDescription)
        }
    }
}
