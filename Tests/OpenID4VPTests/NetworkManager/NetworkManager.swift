import Foundation
@testable import OpenID4VP

class MockNetworkManager: NetworkManaging {
    private var mockResponses: [URL: (response: (responseBody: String, httpUrlResponse: HTTPURLResponse)?, error: Error?)] = [:]
    var recordedRequests: [String: (requestMethod: HTTP_METHOD,requestBody : [String: String]?, requestHeaders : [String: ContentTypes]?)] = [:]
    
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
    
    func printDictionaryAsSwiftCode(_ dictionary: [String: Any]) {
        func formatValue(_ value: Any) -> String {
            if let stringValue = value as? String {
                return "\"\(stringValue)\"" // Wrap strings in quotes
            } else if let dictValue = value as? [String: Any] {
                return formatDictionary(dictValue) // Recursively format nested dictionaries
            } else if let arrayValue = value as? [Any] {
                return formatArray(arrayValue) // Recursively format arrays
            } else {
                return "\(value)" // Fallback for other types
            }
        }
        
        func formatDictionary(_ dict: [String: Any]) -> String {
            let formattedEntries = dict.map { key, value in
                "    \"\(key)\": \(formatValue(value))"
            }.joined(separator: ",\n")
            return "[\n\(formattedEntries)\n]"
        }
        
        func formatArray(_ array: [Any]) -> String {
            let formattedElements = array.map { formatValue($0) }.joined(separator: ", ")
            return "[\(formattedElements)]"
        }
        
        print(formatDictionary(dictionary))
    }
    
    public func sendHTTPRequest(url: String, method: HTTP_METHOD, bodyParams: [String:String]? = nil, headers: [String : ContentTypes]? = nil) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse) {
        
        recordedRequests[url] = (requestMethod: method,requestBody: bodyParams, requestHeaders: headers)
        
        guard let url = URL(string: url) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["response_uri"], className: AuthorizationResponse.className)
        }
        
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
