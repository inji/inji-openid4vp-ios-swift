import Foundation

public final class DCQLHelper {
    private static let className = String(describing: DCQLHelper.self)
    
    private let jsonLdExpander: JsonLdExpanding
    
    public init(jsonLdExpander: JsonLdExpanding) {
        self.jsonLdExpander = jsonLdExpander
    }
    
    public func getMatchingCredentials(inputCredentials: [Credential], dcqlQuery: DCQLQuery) async throws -> MatchingCredentialsResult {
        return try await DcqlEvaluator(jsonLdExpander: jsonLdExpander).evaluate(dcqlQuery, inputCredentials: inputCredentials)
    }
}

public protocol JsonLdExpanding {
    func expand(data: [String:Any]) async throws -> [String: Any]
}
