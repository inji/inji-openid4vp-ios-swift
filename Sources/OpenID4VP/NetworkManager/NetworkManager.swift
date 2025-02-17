import Foundation

public protocol NetworkManaging {
    func sendHTTPRequest(url: URL, method: HTTP_METHOD, bodyParams: String?, headers: [String: String]?) async throws -> String?
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = Logger.getLogTag(String(describing: NetworkManager.self))

    public func sendHTTPRequest(url: URL, method: HTTP_METHOD, bodyParams: String?, headers: [String: String]?) async throws -> String? {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        
        if let headers = headers {
            for (key, value) in headers {
                request.setValue(value, forHTTPHeaderField: key)
            }
        }
        if method == .POST, let body = bodyParams {
            request.httpBody = body.data(using: .utf8)
        }
        
        var exception: Error
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                exception = NetworkRequestException.invalidResponse(message: "Invalid response received")
                Logger.error(NetworkManager.logTag, exception)
                throw exception
            }
            
            guard let bodyString = String(data: data, encoding: .utf8), httpResponse.statusCode == 200 else {
                let exception = NetworkRequestException.networkRequestFailed(message: "\(httpResponse)")
                Logger.error(NetworkManager.logTag, exception)
                throw exception
            }
            return bodyString
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
}


public enum HTTP_METHOD: String, Codable {
    case POST
    case GET
}
