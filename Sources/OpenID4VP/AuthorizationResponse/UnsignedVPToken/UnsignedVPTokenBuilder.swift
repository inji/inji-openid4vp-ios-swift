import Foundation

protocol UnsignedVPTokenBuilder {
    func build() async throws -> [String:Any]
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (payload: Any?, unsignedVPToken : UnsignedVPToken)
}
