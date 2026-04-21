import Foundation

final class WalletSDK {
    private static let className = String(describing: WalletSDK.self)
    
    private let jsonLdExpander: JsonLdExpanding
    
    public init(jsonLdExpander: JsonLdExpanding) {
        self.jsonLdExpander = jsonLdExpander
    }
    
    func getMatchingCredentials(inputCredentials: [Credential], dcqlQuery: DCQLQuery) throws -> QueryEvaluationResult {
        return try DcqlEvaluator().evaluate(dcqlQuery, inputCredentials: inputCredentials)
        
    }
}

public protocol JsonLdExpanding {
    func expand(jsonLd: Any) async throws -> Any
}
