import Foundation

public protocol NetworkManaging {
    func sendHTTPRequest(url: String, method: HTTP_METHOD, bodyParams: [String:String]?, headers: [String: ContentTypes]?) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse)
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = Logger.getLogTag(String(describing: NetworkManager.self))

    public func sendHTTPRequest(url: String, method: HTTP_METHOD, bodyParams: [String:String]? = nil, headers: [String : ContentTypes]? = nil) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse) {

        guard let url = URL(string: url) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["response_uri"], className: AuthorizationResponse.className)
        }

        var exception: Error
        do {
            let (data, httpUrlResponse) = try await self.request(url: url, method: method, bodyParams: bodyParams, headers: headers)
            let body = try processResponseBody(body: data, response: httpUrlResponse)
            return (responseBody: body, httpUrlResponse: httpUrlResponse)
        } catch let error as URLError where error.code == .timedOut {
            exception = NetworkRequestException.networkRequestTimeout
            Logger.error(NetworkManager.logTag, exception)
            throw exception
        } catch {
            exception = NetworkRequestException.networkRequestFailed(message: "\(error.localizedDescription)")
            Logger.error(NetworkManager.logTag, exception)
            throw exception
        }
    }

    private func request(url: URL, method: HTTP_METHOD, bodyParams: [String:String]? = nil, headers: [String: ContentTypes]? = nil) async throws -> (data: Data, httpUrlResponse: HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue

        if let headers = headers {
            for (key, value) in headers {
                request.setValue(value.rawValue, forHTTPHeaderField: key)
            }
        }
        if method == .POST, let body = bodyParams {
            let requestBody = body
                .map { "\($0.key)=\($0.value)" }
                .joined(separator: "&")
            request.httpBody = requestBody.data(using: .utf8)
        }

        var exception: Error
        do {
            let (data, urlResponse) = try await URLSession.shared.data(for: request)
            guard let httpUrlResponse = urlResponse as? HTTPURLResponse else {
                exception = NetworkRequestException.invalidResponse(message: "Invalid response received")
                Logger.error(NetworkManager.logTag, exception)
                throw exception
            }
           return (data, httpUrlResponse)
        } catch let error as URLError where error.code == .timedOut {
            exception = NetworkRequestException.networkRequestTimeout
            Logger.error(NetworkManager.logTag, exception)
            throw exception
        } catch {
            exception = NetworkRequestException.networkRequestFailed(message: "\(error.localizedDescription)")
            Logger.error(NetworkManager.logTag, exception)
            throw exception
        }
    }

    private func processResponseBody(body: Data,response: HTTPURLResponse) throws -> String{
        guard let bodyString = String(data: body, encoding: .utf8), response.statusCode == 200 else {
            let exception = NetworkRequestException.networkRequestFailed(message: "error in conversion \(body)")
            Logger.error(NetworkManager.logTag, exception)
            throw exception
        }
        return bodyString
    }
}


public enum HTTP_METHOD: String {
    case POST
    case GET
}


public enum ContentTypes : String {
    case applicationJson = "application/json"
    case applicationJwt = "application/oauth-authz-req+jwt"
    case applicationFormUrlEncoded = "application/x-www-form-urlencoded"
}
