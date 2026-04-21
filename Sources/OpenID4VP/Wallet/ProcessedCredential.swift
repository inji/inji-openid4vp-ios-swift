protocol ProcessedCredential {
    var credentialId: String { get }
    var credentialFormat: FormatType { get }
}

struct W3cCredential: ProcessedCredential {
    let credentialId: String
    let credentialFormat: FormatType
    let claims: [String: Any]

    init(credentialId: String, credentialFormat: FormatType, claims: [String: Any]) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.claims = claims
    }
}

struct MdocCredential: ProcessedCredential {
    let credentialId: String
    let credentialFormat: FormatType
    let namespaces: [String: [String: Any]]

    init(credentialId: String, credentialFormat: FormatType, namespaces: [String: [String: Any]]) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.namespaces = namespaces
    }
}

struct SdJwtCredential: ProcessedCredential {
    let credentialId: String
    let credentialFormat: FormatType
    let claims: [String: Any]

    init(credentialId: String, credentialFormat: FormatType, claims: [String: Any]) {
        self.credentialId = credentialId
        self.credentialFormat = credentialFormat
        self.claims = claims
    }
}

