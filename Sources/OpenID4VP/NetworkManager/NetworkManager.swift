import Foundation
import Alamofire

public protocol NetworkManaging {
    func sendHTTPRequest(url: String, method: HttpMethod, bodyParams: [String:String]?, headers: [String: String]?) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse)
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = Logger.getLogTag(String(describing: NetworkManager.self))

    public func sendHTTPRequest(url: String, method: HttpMethod, bodyParams requestBody: [String:String]? = nil, headers: [String : String]? = nil) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse) {
        let requestHeaders: HTTPHeaders? = headers?.reduce(into: HTTPHeaders()) { result, header in
            result.add(name: header.key, value: header.value)
        }
        let encoding = getEncoding(for: headers?[Header.contentType.rawValue])
        
        return try await withCheckedThrowingContinuation { continuation in
            AF.request(url, method: method, parameters: requestBody, encoding: encoding, headers: requestHeaders)
                .validate()
                .responseString { response in
                    switch response.result {
                    case .success(let responseBody):
                        if let httpResponse = response.response {
                            continuation.resume(returning: (responseBody, httpResponse))
                        } else {
                            let exception = NetworkRequestException.invalidResponse(message: "Invalid response received")
                            Logger.error(NetworkManager.logTag, exception)
                            continuation.resume(throwing: exception)
                        }
                    case .failure(let error):
                        if let urlError = error.asAFError?.underlyingError as? URLError, urlError.code == .timedOut {
                            let exception = NetworkRequestException.networkRequestTimeout
                            Logger.error(NetworkManager.logTag, exception)
                            continuation.resume(throwing: exception)
                        } else {
                            let exception = NetworkRequestException.networkRequestFailed(message: "\(error.localizedDescription)")
                            Logger.error(NetworkManager.logTag, exception)
                            continuation.resume(throwing: exception)
                        }
                    }
                }
        }
    }
    
    private func getEncoding(for contentType: String?) -> ParameterEncoding {
        switch contentType {
        case "application/json":
            return JSONEncoding.default
        case "application/x-www-form-urlencoded":
            return URLEncoding.default
        default:
            return URLEncoding.default
        }
    }
}


public enum HTTP_METHOD: String {
    case POST
    case GET
}

public typealias HttpMethod = HTTPMethod

enum Header : String {
    case contentType = "Content-Type"
}


public enum ContentTypes : String {
    case applicationJson = "application/json"
    case applicationJwt = "application/oauth-authz-req+jwt"
    case applicationFormUrlEncoded = "application/x-www-form-urlencoded"
}
