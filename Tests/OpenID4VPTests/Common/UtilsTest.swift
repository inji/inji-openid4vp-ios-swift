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
}
