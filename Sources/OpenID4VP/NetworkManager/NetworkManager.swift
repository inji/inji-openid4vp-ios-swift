import Foundation

public protocol NetworkManaging {
    func sendHTTPPostRequest(requestBody: String, url: URL) async throws -> String?
}

public struct NetworkManager: NetworkManaging {
    public static var shared = NetworkManager()
    
    public func sendHTTPPostRequest(requestBody: String, url: URL) async throws -> String? {
        
        Logger.getLogTag(className: String(describing: self))
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = requestBody.data(using: .utf8)
        
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
