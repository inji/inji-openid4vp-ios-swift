import Foundation

class DidPublicKeyResolver : PublicKeyResolver {
    private let didUrl: String
    private let networkManager: NetworkManaging
    static let className = String(describing: DidPublicKeyResolver.self)
    
    init(didUrl: String, networkManager: NetworkManaging) {
        self.didUrl = didUrl
        self.networkManager = networkManager
    }
    
    func resolveKey(header: [String : Any]) async throws -> String {
        let responseBody: [String: Any]
        do {
            responseBody = try await DidWebResolver(didUrl: didUrl, networkManager: networkManager).resolve()
        } catch {
            throw PublicKeyResolutionFailed(
                message: error.localizedDescription,
                className: DidPublicKeyResolver.className
            )
        }
        
        guard let kid = header["kid"] as? String else {
            throw KidExtractionFailed(
                className: DidPublicKeyResolver.className
            )
        }
        return try self.extractPublicKeyMultibase(for: kid, from: responseBody)!
    }
    
    private func extractPublicKeyMultibase(for kid: String, from didDoc: [String: Any]) throws -> String? {
        if let verificationMethod = didDoc["verificationMethod"] as? [[String: Any]] {
            for method in verificationMethod {
                if let id = method["id"] as? String, id == kid,
                   let publicKeyMultibase = method["publicKey"] as? String {
                    return publicKeyMultibase
                }
            }
        }
        
        throw PublicKeyExtractionFailed(
            message: "No matching public key found in DID document for key ID: \(kid)",
            className: DidPublicKeyResolver.className
        )
    }
    
}
