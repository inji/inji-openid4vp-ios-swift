import Foundation

class DidKeyResolver : KeyResolver {
    private let didUrl: String
    private let networkManager: NetworkManaging
    static let className = String(describing: DidKeyResolver.self)
    let DID_RESOLVER = "https://resolver.identity.foundation/1.0/identifiers/"
    
    init(didUrl: String, networkManager: NetworkManaging) {
        self.didUrl = didUrl
        self.networkManager = networkManager
    }
    
    func resolveKey(header: [String : Any]) async throws -> String {
        let host = "\(DID_RESOLVER)\(didUrl)"
        
        guard let url = URL(string: host ) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed",message: "Url creation for did resolution failed" ,className: DidKeyResolver.className)
        }
        
        let (responseBody, _) = (try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.GET, bodyParams: nil, headers: nil))
        
        guard let kid = header["kid"] else {
            throw Logger.handleException(
                exceptionType: "KidExtractionFailed",
                message: "Kid extraction from did document failed",
                className: DidKeyResolver.className
            )
        }
        return try self.extractPublicKeyMultibase(for: kid as! String, from: responseBody)!
    }
    
    private func extractPublicKeyMultibase(for kid: String, from json: String) throws -> String? {
        
        guard let data = json.data(using: .utf8) else {
            throw Logger.handleException(exceptionType: "UTF8Encoding", className: DidKeyResolver.className)
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
                throw Logger.handleException(exceptionType: "PublicKeyNotFound", className: DidKeyResolver.className)
            }
        }
        throw Logger.handleException(exceptionType: "PublicKeyNotFound", message: "No matching public key found in did resolver with the provided key id", className: DidKeyResolver.className)
    }
    
}
