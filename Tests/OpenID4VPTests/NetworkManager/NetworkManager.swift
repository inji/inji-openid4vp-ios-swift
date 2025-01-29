import Foundation
@testable import OpenID4VP

class MockNetworkManager: NetworkManaging {
    var response: String?
    var jwtResponse: String?
    var error: Error?

    func sendHTTPRequest(url: URL, method: HTTP_METHOD, bodyParams: String?, headers: [String: String]?) async throws -> String? {
        if error != nil {
            throw NetworkRequestException.networkRequestFailed(message: "Network Request failed with error")
        }
        if url.path.contains("/verifier/get-auth-request-obj"){
            return jwtResponse
        }
        return response
    }
}
