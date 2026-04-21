
public struct CandidateCredential {
    public let credentialId: String
    public let matchingClaimIndexes: [Int]

    public init(credentialId: String, matchingClaimIndexes: [Int]) {
        self.credentialId = credentialId
        self.matchingClaimIndexes = matchingClaimIndexes
    }
}

public struct ClaimFailure {
    public let claimIndex: Int
    public let reason: String

    public init(claimIndex: Int, reason: String) {
        self.claimIndex = claimIndex
        self.reason = reason
    }
}

public struct QueryMatchResult {
    public let candidateCredentials: [CandidateCredential]?
    public let failedClaims: [ClaimFailure]?
    public let failureReason: String?
    public let allowMultipleCredentials: Bool

    public init(candidateCredentials: [CandidateCredential]? = nil, failedClaims: [ClaimFailure]? = nil,failureReason: String? = nil , allowMultipleCredentials: Bool = false) {
        self.candidateCredentials = candidateCredentials
        self.failedClaims = failedClaims
        self.failureReason = failureReason
        self.allowMultipleCredentials = allowMultipleCredentials
    }
}

public struct CredentialSetRequirement {
    public let options: [[String]]
    public let required: Bool

    public init(options: [[String]], required: Bool) {
        self.options = options
        self.required = required
    }
}

public struct QueryEvaluationResult {
    public let success: Bool
    public let queryMatches: [String: QueryMatchResult]
    public let credentialSets: [CredentialSetQuery]

    public init(success: Bool, queryMatches: [String: QueryMatchResult], credentialSets: [CredentialSetQuery]) {
        self.success = success
        self.queryMatches = queryMatches
        self.credentialSets = credentialSets
    }
}
