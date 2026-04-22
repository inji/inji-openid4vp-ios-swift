import Foundation

private let keyBindingJWT = "kb+jwt"

struct UnsignedSdJwtVPTokenBuilder : UnsignedVPTokenBuilder {
    let authorizationRequest: AuthorizationRequest
    let specVersion: SpecVersion
    let walletMetadata: WalletMetadata?
    private let networkManager: any NetworkManaging

    private static let className = "UnsignedSdJwTVPTokenBuilder"

    init(authorizationRequest: AuthorizationRequest, specVersion: SpecVersion, networkManager: any NetworkManaging = NetworkManager(), walletMetadata: WalletMetadata? = nil) {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        self.networkManager = networkManager
        self.walletMetadata = walletMetadata
    }

    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        var uuidToUnsignedKBJWT = [String: String]()
        var unsignedVPTokens: [UnsignedVPToken] = []

        for index in 0..<credentialInputDescriptorMappings.count {
            let credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            let uuid = UUIDGenerator.generateUUID()
            let (credential, sdJWTPayload) = try extractSdJwtPayload(credentialInputDescriptorMapping.credential, className: Self.className)
            
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: credentialInputDescriptorMapping.format,
                credential: credentialInputDescriptorMapping.credential,
                inputDescriptorId: credentialInputDescriptorMapping.inputDescriptorId,
                identifier: uuid
                )
            
            guard let confirmationKeyClaim = sdJWTPayload["cnf"] as? [String: Any], !confirmationKeyClaim.isEmpty else {
                continue
            }
            
            var jwtSigningALgorithm: String = ""
            if let keyId = confirmationKeyClaim["kid"] as? String {
                let didResolver = DidPublicKeyResolver(networkManager: networkManager)
                let confirmationKey = try await didResolver.resolve(uri: keyId, keyId: nil)
                jwtSigningALgorithm = extractSigningAlgorithm(from: confirmationKey)
            } else {
                throw UnsupportedOperationException(message: "Unsupported cnf format, only 'kid' is supported", className: Self.className)
            }
            
            let jwtHeader = [
                "alg": jwtSigningALgorithm,
                "typ": keyBindingJWT
            ]
            
            let sdHashAlgorithm = sdJWTPayload["_sd_alg"] as? String ?? HashAlgorithm.sha256.rawValue
            let sdHash = try hashData(credential, hashAlgorithm: sdHashAlgorithm, className: Self.className).toBase64UrlEncoded()
            
            let jwtPayload : [String: Any] = [
                "iat": Int(Date().timeIntervalSince1970),
                "aud": authorizationRequest.clientId,
                "nonce": authorizationRequest.nonce,
                "sd_hash": sdHash
            ]
            
            let unsignedJWT = try JWSHandler.createUnsignedJWS(header: jwtHeader, payload: jwtPayload)
            
            uuidToUnsignedKBJWT[uuid] = unsignedJWT
        }
        
        // Ensure deterministic order by sorting by UUID
        for uuid in uuidToUnsignedKBJWT.keys.sorted() {
             let mapping = credentialInputDescriptorMappings.first(where: { $0.identifier == uuid })!
             let credential = mapping.credential.value as! String
             let (kid, alg) = try await resolveSdJwtKeyAndAlg(credential)
             
             unsignedVPTokens.append(UnsignedVPToken(
                format: mapping.format,
                holderKeyReference: kid,
                signatureAlgorithm: alg,
                dataToSign: uuidToUnsignedKBJWT[uuid]!
             ))
        }

        return (
            vpTokenSigningPayload: uuidToUnsignedKBJWT,
            unsignedVPTokens: unsignedVPTokens
        )
    }
}
