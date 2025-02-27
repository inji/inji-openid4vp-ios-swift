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
        let responseBody: [String: Any]
        do {
            responseBody = try await DidWebResolver(didUrl: didUrl, networkManager: networkManager).resolve()
        } catch {
            throw Logger.handleException(exceptionType: "PublicKeyResolutionFailed", message: error.localizedDescription, className: DidPublicKeyResolver.className)
        }
        
        guard let kid = header["kid"] as? String else {
            throw Logger.handleException(
                exceptionType: "KidExtractionFailed",
                message: "Kid extraction from did document failed",
                className: DidPublicKeyResolver.className
            )
        }
        return try self.extractPublicKeyMultibase(for: kid, from: responseBody)!
    }
    
    private func extractPublicKeyMultibase(for kid: String, from didDoc: [String: Any]) throws -> String? {
        if let verificationMethod = didDoc["verificationMethod"] as? [[String: Any]] {
            for method in verificationMethod {
                if let id = method["id"] as? String, id.hasSuffix(kid),
                   let publicKeyMultibase = method["publicKey"] as? String {
                    return publicKeyMultibase
                }
            }
        }
        
        throw Logger.handleException(exceptionType: "PublicKeyNotFound", message: "No matching public key found in did resolver with the provided key id", className: DidPublicKeyResolver.className)
    }
    
}
