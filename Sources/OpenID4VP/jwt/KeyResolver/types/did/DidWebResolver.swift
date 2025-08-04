import Foundation

// This should be moved to other module - vc-verifier once available
class DidWebResolver {
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
    public static let className = String(describing: DidWebResolver.self)
    
    
    private let didMatcher = "^did:\(method):\(methodId)\(params)\(path)\(query)\(fragment)$"
    private let docPath = "/did.json"
    private let wellKnownPath = ".well-known"
    private static let supportedPublicKeyTypes = ["publicKeyMultibase", "publicKeyJwk"]

    
    private let didWebMethod = "web"
    
    let didUrl: String
    let parsedDid: ParsedDID
    let networkManager: NetworkManaging
    
    init(parsedDid: ParsedDID, networkManager: NetworkManaging) {
        self.parsedDid = parsedDid
        self.didUrl = parsedDid.didUrl
        self.networkManager = networkManager
    }
    
    func resolve(verificationaMethodUri kid: String) async throws -> PublicKeyType {
        do {
            
            let urlString = constructDIDUrl(from: self.parsedDid)
            
            let response = try await networkManager.sendHTTPRequest(url: urlString, method: .get, bodyParams: nil, headers: nil)
            guard let responseBody = response.responseBody.data(using: .utf8) else {
                throw InvalidData(
                    message: "Conversion failed: resolved DID response body could not be encoded",
                    className: DidWebResolver.className
                )
            }
            guard let didResponse = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw InvalidData(
                    message: "Conversion failed: resolved DID response is not a valid JSON object",
                    className: DidWebResolver.className
                )
            }
            
            return try self.extractPublicKey(for: kid, from: didResponse)!
        } catch {
            throw DidResolutionFailed(message: error.localizedDescription, className: DidWebResolver.className)
        }
    }

    private func parse() throws -> ParsedDID {
        let didUrlPattern = try! NSRegularExpression(pattern: didMatcher, options: [])
        let nsString = didUrl as NSString
        var sections: [String] = []
        if let match = didUrlPattern.firstMatch(in: didUrl, options: [], range: NSRange(location: 0, length: nsString.length)) {
            sections = (0..<match.numberOfRanges).compactMap {
                Range(match.range(at: $0), in: didUrl).map { String(didUrl[$0]) }
            }
        }
        guard sections.first != nil else {
            throw UnsupportedDidUrl( className: DidWebResolver.className)
        }
        var params: [String: String]? = nil
        if !sections[4].isEmpty {
            params = sections[4].dropFirst().split(separator: ";").reduce(into: [String: String]()) { dict, param in
                let kv = param.split(separator: "=").map(String.init)
                dict[kv[0]] = kv.count > 1 ? kv[1] : ""
            }
        }
        
        return ParsedDID(
            did: "did:\(sections[1]):\(sections[2])",
            method: sections[1],
            id: sections[2],
            didUrl: didUrl,
            params: params,
            path: (sections.count > 6 && !sections[6].isEmpty) ? sections[6] : nil,
            query: (sections.count > 7 && !sections[7].isEmpty) ? String(sections[7].dropFirst()) : nil,
            fragment: (sections.count > 8 && !sections[8].isEmpty) ? String(sections[8].dropFirst()) : nil
        )
    }
    
    private func resolve(parsedDID: ParsedDID) async throws -> [String: Any] {
        do {

            let urlString = constructDIDUrl(from: parsedDID)
            
            let response = try await networkManager.sendHTTPRequest(url: urlString, method: .get, bodyParams: nil, headers: nil)
            guard let responseBody = response.responseBody.data(using: .utf8) else {
                throw InvalidData(
                    message: "Conversion failed: resolved DID response body could not be encoded",
                    className: DidWebResolver.className
                )
            }
            guard let didResponse = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw InvalidData(
                      message: "Conversion failed: resolved DID response is not a valid JSON object",
                      className: DidWebResolver.className
                  )
            }

            return didResponse
        } catch {
            throw DidResolutionFailed(message: error.localizedDescription, className: DidWebResolver.className)
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
                        throw UnsupportedPublicKeyType(className: DidPublicKeyResolver.className)
                    }
                    
                    if let publicKeyMultibase = method["publicKeyMultibase"] as? String{
                        if publicKeyMultibase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            throw InvalidData(
                                message: "publicKeyMultibase cannot be null or empty",
                                className: DidPublicKeyResolver.className
                            )
                        }
                        return try parsePublicKey(from: publicKeyMultibase)
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
                        className: DidPublicKeyResolver.className
                    )
                }
            }
        }
        
        throw PublicKeyExtractionFailed(
            message: "Public key extraction failed for kid: \(kid)",
            className: DidPublicKeyResolver.className
        )
    }
}
