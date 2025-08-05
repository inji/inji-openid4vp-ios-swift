import Foundation
import Base58Swift

protocol BaseDidPublicKeyResolver {
    func resolve(verificationaMethodUri _ : String) async throws -> PublicKeyType
}

// This should be moved to other module - vc-verifier once available
class DidPublicKeyResolver : PublicKeyResolver {
    let networkManager: NetworkManaging
    let didUrl: String
    static let className = String(describing: DidPublicKeyResolver.self)
    var className: String {
        return String(describing: DidPublicKeyResolver.self)
    }
    
    init(didUrl : String, networkManager: NetworkManaging) {
        self.networkManager = networkManager
        self.didUrl = didUrl
    }
    
    func resolveKey(header: [String : Any]) async throws -> PublicKeyType {
        guard let kid = header["kid"] as? String else {
            throw KidExtractionFailed(
                className: self.className
            )
        }
        
        let parsedDID = try parseDid(didUrl)
        
        let resolver : BaseDidPublicKeyResolver = try resolver(parsedDid : parsedDID, networkManager: networkManager)
        
        return try await resolver.resolve(verificationaMethodUri: kid)
    }
    
    private func resolver(parsedDid: ParsedDID, networkManager: NetworkManaging) throws -> BaseDidPublicKeyResolver {
        switch parsedDid.method {
        case .web:
            return DidWebResolver(networkManager: networkManager, parsedDID: parsedDid)
        case .jwk:
            return DidJwkResolver(networkManager: networkManager, parsedDID: parsedDid)
        case .key:
            return DidKeyResolver(networkManager: networkManager, parsedDID: parsedDid)
        }
    }
}

private func parseDid(_ didUrl: String) throws -> ParsedDID {
    let pctEncoded = "(?:%[0-9a-fA-F]{2})"
    let idChar = "(?:[a-zA-Z0-9._-]|\(pctEncoded))"
    let method = "([a-z0-9]+)"
    let methodId = "((?:\(idChar)*:)*(\(idChar)+))"
    let paramChar = "[a-zA-Z0-9_.:%-]"
    let param = ";\(paramChar)+=\(paramChar)*"
    let params = "((\(param))*)"
    let path = "(/[^#?]*)?"
    let query = "([?][^#]*)?"
    let fragment = "(#.*)?"
    let didMatcher = "^did:\(method):\(methodId)\(params)\(path)\(query)\(fragment)$"
    
    let didUrlPattern = try! NSRegularExpression(pattern: didMatcher, options: [])
    let nsString = didUrl as NSString
    var sections: [String] = []
    if let match = didUrlPattern.firstMatch(in: didUrl, options: [], range: NSRange(location: 0, length: nsString.length)) {
        sections = (0..<match.numberOfRanges).compactMap {
            Range(match.range(at: $0), in: didUrl).map { String(didUrl[$0]) }
        }
    }
    guard sections.first != nil else {
        throw UnsupportedDidUrl( className: DidPublicKeyResolver.className)
    }
    var paramsValue: [String: String]? = nil
    if !sections[4].isEmpty {
        paramsValue = sections[4].dropFirst().split(separator: ";").reduce(into: [String: String]()) { dict, param in
            let kv = param.split(separator: "=").map(String.init)
            dict[kv[0]] = kv.count > 1 ? kv[1] : ""
        }
    }
    
    guard let didMethod = DIDMethod(rawValue: sections[1]) else {
        throw UnsupportedDidUrl(className: DidPublicKeyResolver.className)
    }
    
    return ParsedDID(
        did: "did:\(sections[1]):\(sections[2])",
        method: didMethod,
        id: sections[2],
        didUrl: didUrl,
        params: paramsValue,
        path: (sections.count > 6 && !sections[6].isEmpty) ? sections[6] : nil,
        query: (sections.count > 7 && !sections[7].isEmpty) ? String(sections[7].dropFirst()) : nil,
        fragment: (sections.count > 8 && !sections[8].isEmpty) ? String(sections[8].dropFirst()) : nil
    )
}
