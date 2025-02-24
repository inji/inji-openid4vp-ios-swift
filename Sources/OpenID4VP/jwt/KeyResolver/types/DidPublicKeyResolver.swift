import Foundation

class DidPublicKeyResolver : PublicKeyResolver {
    private let didUrl: String
    private let networkManager: NetworkManaging
    static let className = String(describing: DidPublicKeyResolver.self)
    let DID_RESOLVER = "https://resolver.identity.foundation/1.0/identifiers/"
    
    init(didUrl: String, networkManager: NetworkManaging) {
        self.didUrl = didUrl
        self.networkManager = networkManager
    }
    
    func resolveKey(header: [String : Any]) async throws -> String {
        let host = "\(DID_RESOLVER)\(didUrl)"
        
        guard let url = URL(string: host ) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed",message: "Url creation for did resolution failed" ,className: DidPublicKeyResolver.className)
        }
        
        let (responseBody, _) = (try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.GET, bodyParams: nil, headers: nil))
        
        guard let kid = header["kid"] as? String else {
            throw Logger.handleException(
                exceptionType: "KidExtractionFailed",
                message: "Kid extraction from did document failed",
                className: DidPublicKeyResolver.className
            )
        }
        return try self.extractPublicKeyMultibase(for: kid, from: responseBody)!
    }
    
    private func extractPublicKeyMultibase(for kid: String, from json: String) throws -> String? {
        
        guard let data = json.data(using: .utf8) else {
            throw Logger.handleException(exceptionType: "UTF8Encoding", className: DidPublicKeyResolver.className)
        }
        
        do {
            if let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
               let didDocument = json["didDocument"] as? [String: Any],
               let verificationMethod = didDocument["verificationMethod"] as? [[String: Any]] {
                
                for method in verificationMethod {
                    if let id = method["id"] as? String, id.hasSuffix(kid),
                       let publicKeyMultibase = method["publicKey"] as? String {
                        return publicKeyMultibase
                    }
                }
            } else {
                throw Logger.handleException(exceptionType: "PublicKeyNotFound", className: DidPublicKeyResolver.className)
            }
        }
        throw Logger.handleException(exceptionType: "PublicKeyNotFound", message: "No matching public key found in did resolver with the provided key id", className: DidPublicKeyResolver.className)
    }
    
}
