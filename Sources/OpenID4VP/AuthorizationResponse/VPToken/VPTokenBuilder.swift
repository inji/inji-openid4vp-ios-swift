import Foundation

protocol VPTokenBuilder {
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (payload: Any?, unsignedVPToken: UnsignedVPToken),
        vpTokenSigningResult: VPTokenSigningResult,
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int)
}
