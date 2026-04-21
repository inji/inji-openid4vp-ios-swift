import Foundation

public struct SelectedCredential: Codable {
    public let format: FormatType
    public let credential: AnyCodable
    public let credentialId: String
}

public struct Credential : Codable {
    public let format: FormatType
    public let data: AnyCodable
    public let credentialId: String
}
