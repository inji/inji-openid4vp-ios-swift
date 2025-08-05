import Foundation
import Base58Swift

class DidPublicKeyResolver : PublicKeyResolver {
    private let didUrl: String
    private let networkManager: NetworkManaging
    static let className = String(describing: DidPublicKeyResolver.self)
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
    private let didMatcher = "^did:\(method):\(methodId)\(params)\(path)\(query)\(fragment)$"
    
    init(didUrl: String, networkManager: NetworkManaging) {
        self.didUrl = didUrl
        self.networkManager = networkManager
    }
    
    func resolveKey(header: [String : Any]) async throws -> PublicKeyType {
        let parsedDid = try parseDid()
        
        guard let kid = header["kid"] as? String else {
            throw KidExtractionFailed(
                className: DidPublicKeyResolver.className
            )
        }
        
        switch DIDMethod(rawValue: parsedDid.method) {
        case .web:
            return try await DidWebResolver(parsedDid: parsedDid, networkManager: networkManager).resolve(verificationaMethodUri: kid)
        case .jwk:
            return try await DidJwkResolver(parsedDid: parsedDid, networkManager: networkManager).resolve(verificationaMethodUri: kid)
        case .key:
            return try await DidKeyResolver(parsedDid: parsedDid, networkManager: networkManager).resolve(verificationaMethodUri: kid)
        default:
            throw UnsupportedDidUrl(className: Self.className)
        }
    }
    
    private func parseDid() throws -> ParsedDID {
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
}

struct ParsedDID : Equatable {
    let did: String
    let method: String
    let id: String
    let didUrl: String
    var params: [String: String]?
    var path: String?
    var query: String?
    var fragment: String?
}
