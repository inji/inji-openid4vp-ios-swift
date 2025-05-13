import Foundation
import Alamofire

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = Logger.getLogTag(String(describing: NetworkManager.self))
    
    public func sendHTTPRequest(url: String, method: HttpMethod, bodyParams requestBody: [String:Any]? = nil, headers: [String : String]? = nil) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse) {
        let requestHeaders: HTTPHeaders? = headers?.reduce(into: HTTPHeaders()) { result, header in
            result.add(name: header.key, value: header.value)
        }
        let contentType = headers?[Header.contentType.rawValue]
        let encoding = getEncoding(for: contentType)
        
        return try await withCheckedThrowingContinuation { continuation in
            AF.request(url, method: method, parameters: formatRequestBody(requestBody, for: contentType), encoding: encoding, headers: requestHeaders)
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
        if contentType == ContentTypes.applicationJson.rawValue {
            return JSONEncoding.default
        } else {
            return URLEncoding.default
        }
    }
    
    private func formatRequestBody(_ body: [String: Any]?, for contentType: String?) -> Parameters {
        guard let body = body else { return [:] }
        
        if contentType == ContentTypes.applicationJson.rawValue {
            return body
        } else {
            return flattenFormURLEncoded(body)
        }
    }
    
    private func flattenFormURLEncoded(_ input: [String: Any]?) -> [String: String] {
        var result: [String: String] = [:]
        
        func recurse(prefix: String, value: Any) {
            switch value {
            case let dict as [String: Any]:
                for (key, nestedValue) in dict {
                    let newPrefix = "\(prefix)[\(key)]"
                    recurse(prefix: newPrefix, value: nestedValue)
                }
                
            case let array as [Any]:
                for (index, item) in array.enumerated() {
                    let newPrefix = "\(prefix)[\(index)]"
                    recurse(prefix: newPrefix, value: item)
                }
                
            case let str as String:
                result[prefix] = str
                
            case let number as NSNumber:
                result[prefix] = number.stringValue
                
            default:
                result[prefix] = "\(value)"
            }
        }
        
        for (key, value) in input ?? [:] {
            recurse(prefix: key, value: value)
        }
        
        return result
    }
    
}
