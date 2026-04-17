import Foundation

public struct SelectedCredential: Codable {
    public let format: FormatType
    public let credential: AnyCodable
    public let credentialId: String
}

