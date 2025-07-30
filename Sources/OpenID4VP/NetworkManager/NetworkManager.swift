import Foundation
import Alamofire

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = OpenID4VPException.getLogTag(String(describing: NetworkManager.self))
    
    public func sendHTTPRequest(
        url: String,
        method: HttpMethod,
        bodyParams requestBody: [String: String]? = nil,
        headers: [String: String]? = nil
    ) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse) {
        
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
                        continuation.resume(returning: (responseBody, httpResponse))
                    } else {
                        let exception = NetworkRequestException.invalidResponse(message: "Invalid response received")
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        continuation.resume(throwing: exception)
                    }
                case .failure(let error):
                    if let urlError = error.asAFError?.underlyingError as? URLError, urlError.code == .timedOut {
                        let exception = NetworkRequestException.networkRequestTimeout
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        print("url failure: \(url)")
                        continuation.resume(throwing: exception)
                    } else {
                        let exception = NetworkRequestException.networkRequestFailed(message: "\(error.localizedDescription)")
                        OpenID4VPException.error(NetworkManager.logTag, exception)
                        print("url failure: \(url)")
                        continuation.resume(throwing: exception)
                    }
                }
            }
        }
    }
    
    private func getEncoding(for contentType: String?) -> ParameterEncoding {
        if contentType == ContentTypes.applicationJson.rawValue {
            return JSONEncoding.default
        } else {
            return URLEncoding.default
        }
    }
    
    private func formatRequestBody(_ body: [String: String]?, for contentType: String?) -> Parameters {
        return body ?? [:]
    }
}
