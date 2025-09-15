import Foundation

internal struct CredentialInputDescriptorMapping {
    let format: FormatType
    let credential: AnyCodable
    let inputDescriptorId: String
    var identifier: String?
    var nestedPath: String?
    
    init(format: FormatType, credential: AnyCodable, inputDescriptorId: String) {
        self.format = format
        self.credential = credential
        self.inputDescriptorId = inputDescriptorId
        self.identifier = nil
        self.nestedPath = nil
    }
}
