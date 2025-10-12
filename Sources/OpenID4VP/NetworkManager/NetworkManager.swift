import Foundation
import Alamofire

public struct NetworkResponse : Codable {
    public let statusCode: Int
    public let body: String
    public let headers: [String: String]
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = OpenID4VPException.getLogTag(String(describing: NetworkManager.self))
    
    /// Sends an HTTP request to the given URL and returns a parsed NetworkResponse.
    /// - Parameters:
    ///   - url: The request URL as a string.
    ///   - method: The HTTP method to use for the request.
    ///   - bodyParams: Optional request body parameters; treated as an empty set if `nil`.
    ///   - headers: Optional request headers; the `Content-Type` header (if present) is used to determine request encoding.
    /// - Returns: A `NetworkResponse` containing the HTTP status code, response body as a UTF-8 string (empty string if absent or undecodable), and response headers as a dictionary.
    /// - Throws: `NetworkRequestException.invalidResponse` if no HTTP response is received; `NetworkRequestException.networkRequestTimeout` if the request times out; `NetworkRequestException.networkRequestFailed` for other request failures.
    public func sendHTTPRequest(
        url: String,
        method: HttpMethod,
        bodyParams requestBody: [String: String]? = nil,
        headers: [String: String]? = nil
    ) async throws -> NetworkResponse {
        
        let requestHeaders: HTTPHeaders? = headers?.reduce(into: HTTPHeaders()) { result, header in
            result.add(name: header.key, value: header.value)
        }
        
        let contentType = headers?[Header.contentType.rawValue]
        let encoding = getEncoding(for: contentType)
        
        return try await withCheckedThrowingContinuation { continuation in
            AF.request(
                url,
                method: method,
                parameters: formatRequestBody(requestBody, for: contentType),
                encoding: encoding,
                headers: requestHeaders
            )
            .validate()
            .response { response in
                switch response.result {
                case .success:
                    if let httpResponse = response.response {
                        let responseBody: String
                        if let data = response.data, !data.isEmpty {
                            responseBody = String(data: data, encoding: .utf8) ?? ""
                        } else {
                            responseBody = ""
                        }
                        let networkResponse = NetworkResponse(
                            statusCode: httpResponse.statusCode,
                            body: responseBody,
                            headers: httpResponse.headers.dictionary
                        )
                        continuation.resume(returning: networkResponse)
                    } else {
                        let exception = NetworkRequestException.invalidResponse(message: "Invalid response received")
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        continuation.resume(throwing: exception)
                    }
                case .failure(let error):
                    if let urlError = error.asAFError?.underlyingError as? URLError, urlError.code == .timedOut {
                        let exception = NetworkRequestException.networkRequestTimeout
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        continuation.resume(throwing: exception)
                    } else {
                        let exception = NetworkRequestException.networkRequestFailed(message: "\(error.localizedDescription)")
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        continuation.resume(throwing: exception)
                    }
                }
            }
        }
    }
    
    private func getEncoding(for contentType: String?) -> ParameterEncoding {
            return URLEncoding.default
    }
    
    private func formatRequestBody(_ body: [String: String]?, for contentType: String?) -> Parameters {
        return body ?? [:]
    }
}