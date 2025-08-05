import Foundation

class DidWebResolver : BaseDidPublicKeyResolver {
    private static let pctEncoded = "(?:%[0-9a-fA-F]{2})"
    private static let idChar = "(?:[a-zA-Z0-9._-]|\(pctEncoded))"
    private static let method = "([a-z0-9]+)"
    private static let methodId = "((?:\(idChar)*:)*(\(idChar)+))"
    private static let paramChar = "[a-zA-Z0-9_.:%-]"
    private static let param = ";\(paramChar)+=\(paramChar)*"
    private static let params = "((\(param))*)"
    private static let path = "(/[^#?]*)?"
    private static let query = "([?][^#]*)?"
    private static let fragment = "(#.*)?"
    private static let className: String = String(describing: DidWebResolver.self)
    
    private let didMatcher = "^did:\(method):\(methodId)\(params)\(path)\(query)\(fragment)$"
    private let docPath = "/did.json"
    private let wellKnownPath = ".well-known"
    let parsedDid: ParsedDID
    let networkManager: NetworkManaging
    private static let supportedPublicKeyTypes = ["publicKeyMultibase", "publicKeyJwk", "publicKeyPem", "publicKeyHex"]
    
    init(networkManager: NetworkManaging, parsedDID: ParsedDID) {
        self.networkManager = networkManager
        self.parsedDid = parsedDID
    }
    
    func resolve(verificationaMethodUri kid: String) async throws -> PublicKeyType {
        do {
            
            let urlString = constructDIDUrl(from: parsedDid)
            
            let response = try await networkManager.sendHTTPRequest(url: urlString, method: .get, bodyParams: nil, headers: nil)
            guard let responseBody = response.responseBody.data(using: .utf8) else {
                throw InvalidData(
                    message: "Conversion failed: resolved DID response body could not be encoded",
                    className: Self.className
                )
            }
            guard let didResponse = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw InvalidData(
                    message: "Conversion failed: resolved DID response is not a valid JSON object",
                    className: Self.className
                )
            }
            
            return try self.extractPublicKey(for: kid, from: didResponse)!
        } catch {
            throw DidResolutionFailed(message: error.localizedDescription, className: Self.className)
        }
    }
    
    private func constructDIDUrl(from parsedDID: ParsedDID) -> String {
        let idComponents = parsedDID.id.split(separator: ":").map(String.init)
        let baseDomain = idComponents.first!
        let path = idComponents.dropFirst().joined(separator: "/")
        let urlPath = path.isEmpty ? "\(wellKnownPath)\(docPath)" : "\(path)\(docPath)"
        
        return "https://\(baseDomain)/\(urlPath)"
    }
    
    private func extractPublicKey(for kid: String, from didDoc: [String: Any]) throws -> PublicKeyType? {
        if let verificationMethods = didDoc["verificationMethod"] as? [[String: Any]] {
            for method in verificationMethods {
                if let id = method["id"] as? String, id == kid {
                    
                    if !Self.supportedPublicKeyTypes.contains(where: { method[$0] != nil }) {
                        throw UnsupportedPublicKeyType(className: Self.className)
                    }
                    
                    if method.keys.contains("publicKeyMultibase") {
                        let publicKeyMultibase = method["publicKeyMultibase"] as? String
                        if isNullOrEmpty(publicKeyMultibase) {
                            throw InvalidData(
                                message: "publicKeyMultibase cannot be null or empty",
                                className: Self.className
                            )
                        }
                        return try parsePublicKey(from: publicKeyMultibase!)
                    }
                    
                    if let jwk = method["publicKeyJwk"] as? [String: Any] {
                        return try publicKeyFromJWK(jwk)
                    }
                    
                    if let publicKeyPem = method["publicKeyPem"] as? String {
                        return try publicKeyFromPEM(publicKeyPem)
                    }
                    
                    if let publicKeyHex = method["publicKeyHex"] as? String {
                        return publicKeyFromHex(publicKeyHex)
                    }
                    
                    
                    throw PublicKeyExtractionFailed(
                        message: "unsupported verification material or no publicKeyMultibase or publicKeyJwk",
                        className: Self.className
                    )
                }
            }
        }
        
        throw PublicKeyExtractionFailed(
            message: "Public key extraction failed for kid: \(kid)",
            className: Self.className
        )
    }
}
