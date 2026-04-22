import Foundation

public struct SelectedCredential: Codable {
    public let format: FormatType
    public let credential: AnyCodable
    public let credentialId: String

    public init(format: FormatType, credential: AnyCodable, credentialId: String) {
       self.format = format
       self.credential = credential
       self.credentialId = credentialId
   }
}

public struct Credential : Codable {
    public let format: FormatType
    public let data: AnyCodable
    public let credentialId: String

    public init(format: FormatType, data: AnyCodable, credentialId: String) {
          self.format = format
          self.data = data
          self.credentialId = credentialId
      }
}
