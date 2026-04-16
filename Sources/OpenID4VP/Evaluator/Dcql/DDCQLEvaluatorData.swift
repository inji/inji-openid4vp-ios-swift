public protocol ProcessedCredential {
    var credentialId: String { get }
    var credentialFormat: String { get }
    var cryptographicHolderBinding: Bool { get }
}

public struct W3cCredential: ProcessedCredential {
    public let credentialId: String
    public let credentialFormat: String
    public let type: [String]
    public let claims: [String: Any]
    public let cryptographicHolderBinding: Bool

    public init(credentialId: String, credentialFormat: String, type: [String], claims: [String: Any], cryptographicHolderBinding: Bool = true) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.type = type
        self.claims = claims
        self.cryptographicHolderBinding = cryptographicHolderBinding
    }
}

public struct MdocCredential: ProcessedCredential {
    public let credentialId: String
    public let credentialFormat: String
    public let doctype: String
    public let namespaces: [String: [String: Any]]
    public let cryptographicHolderBinding: Bool

    public init(credentialId: String, credentialFormat: String, doctype: String, namespaces: [String: [String: Any]], cryptographicHolderBinding: Bool = true) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.doctype = doctype
        self.namespaces = namespaces
        self.cryptographicHolderBinding = cryptographicHolderBinding
    }
}

public struct SdJwtCredential: ProcessedCredential {
    public let credentialId: String
    public let credentialFormat: String
    public let vct: String
    public let claims: [String: Any]
    public let cryptographicHolderBinding: Bool

    public init(credentialId: String, credentialFormat: String, vct: String, claims: [String: Any], cryptographicHolderBinding: Bool = true) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.vct = vct
        self.claims = claims
        self.cryptographicHolderBinding = cryptographicHolderBinding
    }
}

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
    public let allowMultipleCredentials: Bool

    public init(candidateCredentials: [CandidateCredential]? = nil, failedClaims: [ClaimFailure]? = nil, allowMultipleCredentials: Bool = false) {
        self.candidateCredentials = candidateCredentials
        self.failedClaims = failedClaims
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
    public let credentialSets: [CredentialSetRequirement]

    public init(success: Bool, queryMatches: [String: QueryMatchResult], credentialSets: [CredentialSetRequirement]) {
        self.success = success
        self.queryMatches = queryMatches
        self.credentialSets = credentialSets
    }
}
