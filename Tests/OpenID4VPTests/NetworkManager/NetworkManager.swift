import Foundation
@testable import OpenID4VP

class MockNetworkManager: NetworkManaging {
    private var mockResponses: [URL: (response: (responseBody: String, httpUrlResponse: HTTPURLResponse)?, error: Error?)] = [:]
    
    func setMockResponse(for url: URL, response: (responseBody: String, httpUrlResponse: HTTPURLResponse?)? = nil, responseBody: String? = nil, error: Error? = nil) {
        let defaultHttpUrlResponse = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!
        
        var finalResponse: (responseBody: String, httpUrlResponse: HTTPURLResponse)?
        
        if let response = response {
            let urlResponse = response.httpUrlResponse ?? defaultHttpUrlResponse
            finalResponse = (responseBody: response.responseBody, httpUrlResponse: urlResponse)
        } else if let responseBody = responseBody {
            finalResponse = (responseBody: responseBody, httpUrlResponse: defaultHttpUrlResponse)
        }
        
        mockResponses[url] = (finalResponse, error)
    }
    
    func clearMockResponses(){
        mockResponses = [:]
    }
    
    public func sendHTTPRequest(url: URL, method: HTTP_METHOD, bodyParams: String? = nil, headers: [String : String]? = nil) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse) {
        let defaultHttpUrlResponse = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "text/json"])!
        if let (response, error) = mockResponses[url] {
            if let error = error {
                throw error
            }
            
            return (response ?? (responseBody: "Success: Request completed successfully.", httpUrlResponse: defaultHttpUrlResponse))
        }
        return (responseBody: "Success: Request completed successfully.", httpUrlResponse: defaultHttpUrlResponse)
    }
}
