import Foundation

public struct VerifierResponse {
    let statusCode: Int
    /// Holds redirect_uri from the Verifier response body
    let redirectUri: String?
    /// Holds additional parameters in JSON string format other than redirect_uri
    let additionalParams: String?
    let headers: [String: String]
    private let responseBody: String
    
    init(statusCode: Int, responseBody: String = "", redirectUri: String? = nil, additionalParams: String? = nil, headers: [String: String]) {
        self.statusCode = statusCode
        self.responseBody = responseBody
        self.redirectUri = redirectUri
        self.additionalParams = additionalParams
        self.headers = headers
    }
        
    
    func isOk() -> Bool {
        return (200...299).contains(statusCode)
    }
    
    internal func body() -> String {
        return responseBody
    }
}
