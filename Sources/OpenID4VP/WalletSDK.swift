import Foundation

final class WalletSDK {
    static func getMatchingCredentials(inputCredentials: [any ProcessedCredential], dcqlQuery: DCQLQuery) -> QueryEvaluationResult {
        return DcqlEvaluator().evaluate(dcqlQuery, inputCredentials: inputCredentials)
    }
}
