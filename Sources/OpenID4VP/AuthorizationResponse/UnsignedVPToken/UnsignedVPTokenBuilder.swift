import Foundation

typealias VPTokenSigningPayload = Any

protocol UnsignedVPTokenBuilder {
    var specVersion: SpecVersion { get }
    var authorizationRequest: AuthorizationRequest { get }
    var walletMetadata: WalletMetadata? { get }
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPTokens: [UnsignedVPToken])
}
