import Foundation

class DidPublicKeyResolver : PublicKeyResolver {
    private let didUrl: String
    private let networkManager: NetworkManaging
    static let className = String(describing: DidPublicKeyResolver.self)
    private static let supportedPublicKeyTypes = ["publicKeyMultibase"]

    
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
        if let verificationMethods = didDoc["verificationMethod"] as? [[String: Any]] {
            for method in verificationMethods {
                if let id = method["id"] as? String, id == kid {

                    if !Self.supportedPublicKeyTypes.contains(where: { method[$0] != nil }) {
                        throw UnsupportedPublicKeyType(className: DidPublicKeyResolver.className)
                    }

                    let publicKeyMultibase = method["publicKeyMultibase"] as? String
                    if publicKeyMultibase?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true {
                        throw InvalidData(
                            message: "publicKeyMultibase cannot be null or empty",
                            className: DidPublicKeyResolver.className
                        )
                    }
                    return publicKeyMultibase!
                }
            }
        }

        throw PublicKeyExtractionFailed(
            message: "Public key extraction failed for kid: \(kid)",
            className: DidPublicKeyResolver.className
        )
    }
    
    
}
