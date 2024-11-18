import Foundation
@testable import OpenID4VP

class MockNetworkManager: NetworkManaging {
    var response: HTTPURLResponse?
    var error: Error?

    func sendHTTPRequest(url: URL, method: HTTP_METHOD, body: String?, headers: [String: String]?) async throws -> String? {
        if error != nil {
            throw NetworkRequestException.networkRequestFailed(message: "Network Request failed with error response: response")
        }
        return "Success: Request completed successfully."
    }
}
