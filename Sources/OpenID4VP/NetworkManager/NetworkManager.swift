import Foundation

public protocol NetworkManaging {
    func sendHTTPRequest(url: URL, method: HTTP_METHOD, body: String?, headers: [String: String]?) async throws -> String?
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    static let logTag = Logger.getLogTag(String(describing: NetworkManager.self))
    
    public func sendHTTPRequest(url: URL, method: HTTP_METHOD, body: String?, headers: [String: String]?) async throws -> String? {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        
        switch method {
        case .POST:
            request.setValue(headers?["Content-Type"], forHTTPHeaderField: "Content-Type")
            request.httpBody = body?.data(using: .utf8)
        case .GET:
            ()
        }
        
        var exception: Error
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                exception = NetworkRequestException.invalidResponse(message: "Invalid response received")
                Logger.error(NetworkManager.logTag, exception)
                throw exception
            }
            
            if httpResponse.statusCode == 200 {
                return "Success: Request completed successfully."
            } else {
                exception = NetworkRequestException.networkRequestFailed(message: "\(httpResponse)")
                Logger.error(NetworkManager.logTag, exception)
                throw exception
            }
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
