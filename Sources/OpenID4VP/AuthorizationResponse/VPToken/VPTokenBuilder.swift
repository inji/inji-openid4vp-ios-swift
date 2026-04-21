import Foundation

protocol VPTokenBuilder {
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int)
}
