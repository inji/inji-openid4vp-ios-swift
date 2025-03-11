import XCTest
@testable import OpenID4VP

final class NetworkManagerTests: XCTestCase {
    struct TestCase {
        let input: String
        let expectedError: String
    }

    func testThrowErrorWhenInvalidUrlIsPassedAsInput() async throws {
        let networkManager = NetworkManager()
        let testCases: [TestCase] = [
            TestCase(input: "", expectedError: "Provided URL is invalid to proceed with making request"),
            TestCase(input: "invalid-url", expectedError: "Network request failed with error response - Network request failed with error response - unsupported URL"),
            TestCase(input: "http://exa<mpl>e.com", expectedError: "Provided URL is invalid to proceed with making request"),
        ]
        
        for testCase in testCases {
            do {
                _ = try await networkManager.sendHTTPRequest(url: testCase.input, method: .GET)
                XCTFail("Invalid URL error should have been captured but no error was thrown")
            } catch {
                print("error \(error)")
                XCTAssertEqual(testCase.expectedError, error.localizedDescription, "Error - \(testCase.expectedError) should be thrown but got \(error.localizedDescription)")
            }
        }
    }
    
}
