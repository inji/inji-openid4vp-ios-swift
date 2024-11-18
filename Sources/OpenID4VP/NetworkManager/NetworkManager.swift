import Foundation

public protocol NetworkManaging {
    func sendHTTPRequest(url: URL, method: HTTP_METHOD, body: String?, headers: [String: String]?) async throws -> String?
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    
    public func sendHTTPRequest(url: URL, method: HTTP_METHOD, body: String?, headers: [String: String]?) async throws -> String? {
        
        Logger.getLogTag(className: String(describing: self))
        
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        
        switch method {
        case .POST:
            request.setValue(headers?["Content-Type"], forHTTPHeaderField: "Content-Type")
            request.httpBody = body?.data(using: .utf8)
        case .GET:
            ()
        }
        
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                Logger.error("Invalid response received.")
                throw NetworkRequestException.invalidResponse
            }
            
            if httpResponse.statusCode == 200 {
                return "Success: Request completed successfully."
            } else {
                Logger.error("Request failed with status code: \(httpResponse.statusCode)")
                throw NetworkRequestException.networkRequestFailed(message: "Network Request failed with error response: \(httpResponse)")
            }
        } catch let error as URLError where error.code == .timedOut {
            Logger.error("Network request timed out.")
            throw NetworkRequestException.interruptedIOException
        } catch {
            Logger.error("Network request failed due to unknown error: \(error.localizedDescription)")
            throw NetworkRequestException.networkRequestFailed(message: error.localizedDescription)
        }
    }
}


public enum HTTP_METHOD: String, Codable {
    case POST
    case GET
}
