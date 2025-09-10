import Foundation

class SdJwtVPTokenBuilder : VPTokenBuilder {
    private let vpTokenSigningResult: SdJwtVpTokenSigningResult
    private let credentials: [String : String]
    private let unsignedVpTokens: UnsignedSdJWTVPToken
    private let uuid : String
    private let className = String(describing: SdJwtVPTokenBuilder.self)
    
    init(
        vpTokenSigningResult: SdJwtVpTokenSigningResult,
        credentials: [String : String],
        unsignedVpTokens: UnsignedSdJWTVPToken,
        uuid: String
    ) {
        self.vpTokenSigningResult = vpTokenSigningResult
        self.credentials = credentials
        self.unsignedVpTokens = unsignedVpTokens
        self.uuid = uuid
    }
    
    func build() throws -> VPToken {
        if let sdJwtCredential = credentials[uuid] {
            guard let unsignedKBJwt = unsignedVpTokens.uuidToUnsignedKBT[uuid] else {
                throw MissingInput(fieldPath: uuid, message: "Missing unsigned Key Binding JWT for uuid: \(uuid)", className: className)
            }
            
            guard let signature = vpTokenSigningResult.uuidToKbJWTSignature[uuid] else {
                throw MissingInput(fieldPath: uuid, message: "Missing Key Binding JWT signature for uuid: \(uuid)", className: className)
            }
            
            let sdJwtVpTokenValue = "\(sdJwtCredential)\(unsignedKBJwt).\(signature)"
            
            return SdJwtVPToken(value: sdJwtVpTokenValue)
        } else {
            throw MissingInput(fieldPath: uuid, message: "Missing SD-JWT credential for uuid: \(uuid)", className: className)
        }
    }
}
