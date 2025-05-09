import XCTest
@testable import OpenID4VP

final class Base64EncoderTests: XCTestCase {
    
    func testEncodeToBase64Url() {
        let testCases: [TestCase<Data, String>] = [
            TestCase(input: "Hello, World!".data(using: .utf8)!, expectedOutput: "SGVsbG8sIFdvcmxkIQ"),
            TestCase(input: Data(), expectedOutput: ""),
            TestCase(input: "!@#$%^&*()".data(using: .utf8)!, expectedOutput: "IUAjJCVeJiooKQ"),
            TestCase(input: Data([0xFF, 0xD8, 0xFF, 0xE0]), expectedOutput: "_9j_4A")
        ]
        
        for testCase in testCases {
            let result = Base64Encoder.encodeToBase64Url(testCase.input)
            XCTAssertEqual(result, testCase.expectedOutput, "Base64 URL encoding failed for input: \(testCase.input)")
        }
    }
}
