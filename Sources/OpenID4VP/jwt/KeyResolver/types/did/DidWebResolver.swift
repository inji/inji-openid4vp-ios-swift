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
    
    
    private let DID_MATCHER = "^did:\(method):\(methodId)\(params)\(path)\(query)\(fragment)$"
    private let DOC_PATH = "/did.json"
    
    private let didWebMethod = "web"
    
    let didUrl: String
    let networkManager: NetworkManaging
    
    init(didUrl: String, networkManager: NetworkManaging) {
        self.didUrl = didUrl
        self.networkManager = networkManager
    }
    
    // Throws UnsupportedDidUrl or DidResultionFailed with error description
    func resolve() async throws -> [String: Any] {
        let parsedDid = try parse()
        guard parsedDid.method == didWebMethod else {
            throw Logger.handleException(exceptionType: "UnsupportedDidUrl", message: "Given did url is not supported", className: DidWebResolver.className)
        }
        let result = try await resolve(parsedDID: parsedDid)
        return result
    }
    
    private func parse() throws -> ParsedDID {
        let didUrlPattern = try! NSRegularExpression(pattern: DID_MATCHER, options: [])
        let nsString = didUrl as NSString
        var sections: [String] = []
        if let match = didUrlPattern.firstMatch(in: didUrl, options: [], range: NSRange(location: 0, length: nsString.length)) {
            sections = (0..<match.numberOfRanges).compactMap {
                Range(match.range(at: $0), in: didUrl).map { String(didUrl[$0]) }
            }
        }
        guard sections.first != nil else {
            throw Logger.handleException(exceptionType: "UnsupportedDidUrl", message: "Given did url is not supported", className: DidWebResolver.className)
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
            let path = parsedDID.id.split(separator: ":").map { String($0) }.map { $0.removingPercentEncoding ?? $0 }.joined(separator: "/")
            guard let url = URL(string: "https://\(path)\(DOC_PATH)") else {
                throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["did_url"], className: DidWebResolver.className)
            }
            
            let response = try await networkManager.sendHTTPRequest(url: url, method: .GET)
            guard let responseBody = response.responseBody.data(using: .utf8) else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: DidWebResolver.className
                )
            }
            guard let didResponse = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: DidWebResolver.className
                )
            }

            return didResponse
        } catch {
            throw Logger.handleException(exceptionType: "DidResultionFailed", message: error.localizedDescription, className: DidWebResolver.className)
        }
    }
}


fileprivate struct ParsedDID : Equatable {
    let did: String
    let method: String
    let id: String
    let didUrl: String
    var params: [String: String]?
    var path: String?
    var query: String?
    var fragment: String?
}
