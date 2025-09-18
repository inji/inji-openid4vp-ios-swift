import Foundation

protocol UnsignedVPTokenBuilder {
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPToken : UnsignedVPToken)
}
