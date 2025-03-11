import XCTest
@testable import OpenID4VP

final class NetworkManagerTests: XCTestCase {
    func testThrowErrorWhenInvalidUrlIsPassedAsInput() async throws {
        let networkManager = NetworkManager()
        
        do {
            try await networkManager.sendHTTPRequest(url: "invalid-url", method: .GET)
            XCTFail("Invalid URL error should have been captured but no error was thrown")
        } catch {
            XCTAssertEqual("Network request failed with error response - Network request failed with error response - unsupported URL", error.localizedDescription)
        }
    }
}
