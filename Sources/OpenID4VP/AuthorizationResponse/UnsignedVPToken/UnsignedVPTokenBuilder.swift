import Foundation

typealias VPTokenSigningPayload = LdpVPToken

protocol UnsignedVPTokenBuilder {
    var specVersion: SpecVersion { get }
    var authorizationRequest: AuthorizationRequest { get }
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken)
}
