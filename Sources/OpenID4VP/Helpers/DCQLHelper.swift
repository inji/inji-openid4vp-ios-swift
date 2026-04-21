import Foundation

public final class DCQLHelper {
    private static let className = String(describing: DCQLHelper.self)
    
    private let jsonLdExpander: JsonLdExpanding
    
    public init(jsonLdExpander: JsonLdExpanding) {
        self.jsonLdExpander = jsonLdExpander
    }
    
    func getMatchingCredentials(inputCredentials: [Credential], dcqlQuery: DCQLQuery) throws -> MatchingCredentialsResult {
        return try DcqlEvaluator(jsonLdExpander: jsonLdExpander).evaluate(dcqlQuery, inputCredentials: inputCredentials)
    }
}

public protocol JsonLdExpanding {
    func expand(data: [String:Any]) async throws -> [String: Any]
}
