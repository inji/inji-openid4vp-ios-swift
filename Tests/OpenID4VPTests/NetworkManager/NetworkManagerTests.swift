import XCTest
@testable import OpenID4VP

import Foundation
import Alamofire

class MockURLProtocol: URLProtocol {
    
    static var mockResponse: (Data?, HTTPURLResponse?, Error?)?

    override class func canInit(with request: URLRequest) -> Bool {
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        if let (data, response, error) = MockURLProtocol.mockResponse {
            if let response = response {
                self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }
            if let data = data {
                self.client?.urlProtocol(self, didLoad: data)
            }
            if let error = error {
                self.client?.urlProtocol(self, didFailWithError: error)
            }
        }
        self.client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}


final class NetworkManagerTests: XCTestCase {
    struct TestCase {
        let input: String
        let expectedError: String
    }

    func testThrowErrorWhenInvalidUrlIsPassedAsInput() async throws {
        let networkManager = NetworkManager()
        let testCases: [TestCase] = [
            TestCase(input: "", expectedError: "Network request failed with error response - URL is not valid: "),
            TestCase(input: "invalid-url", expectedError: "Network request failed with error response - URLSessionTask failed with error: unsupported URL"),
            TestCase(input: "http://exa<mpl>e.com", expectedError: "Network request failed with error response - URL is not valid: http://exa<mpl>e.com"),
        ]
        
        for testCase in testCases {
            do {
                _ = try await networkManager.sendHTTPRequest(url: testCase.input, method: .get)
                XCTFail("Invalid URL error should have been captured but no error was thrown")
            } catch {
                XCTAssertEqual(testCase.expectedError, error.localizedDescription, "Error - \(testCase.expectedError) should be thrown but got \(error.localizedDescription)")
            }
        }
    }
    
}
