import Foundation

internal struct CredentialToCredentialQueryIdMapping {
    let format: FormatType
    let credential: AnyCodable
    let credentialQueryId: String
    
    init(format: FormatType, credential: AnyCodable, credentialQueryId: String) {
        self.format = format
        self.credential = credential
        self.credentialQueryId = credentialQueryId
    }
}
