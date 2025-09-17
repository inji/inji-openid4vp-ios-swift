import Foundation

protocol UnsignedVPTokenBuilder {
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (payload: Any?, unsignedVPToken : UnsignedVPToken)
}
