import Foundation

typealias VPTokenSigningPayload = LdpVPToken

protocol UnsignedVPTokenBuilder {
    var specVersion: SpecVersion { get }
    var authorizationRequest: AuthorizationRequestV2 { get }
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken)
}
