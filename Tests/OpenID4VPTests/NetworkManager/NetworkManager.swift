import Foundation
@testable import OpenID4VP

class MockNetworkManager: NetworkManaging {
    private var mockResponses: [URL: (response: String?, error: Error?)] = [:]
    
    func setMockResponse(for url: URL, response: String? = nil, error: Error? = nil) {
        mockResponses[url] = (response, error)
    }
    
    func sendHTTPRequest(url: URL, method: HTTP_METHOD, bodyParams: String?, headers: [String: String]?) async throws -> String? {
        if let (response, error) = mockResponses[url] {
            if let error = error {
                throw error
            }
            return response ?? "Success: Request completed successfully."
        }
        return "Success: Request completed successfully."
    }
}
