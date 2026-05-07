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
            let uuid = UUIDGenerator.generateUUID()
            let mapping = credentialInputDescriptorMappings[index]
            
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: mapping.format,
                credential: mapping.credential,
                inputDescriptorId: mapping.inputDescriptorId,
                identifier: uuid
            )
            
            if let result = try await prepareUnsignedKeyBinding(
                credentialData: mapping.credential,
                format: mapping.format,
                clientId: authorizationRequest.clientId,
                nonce: authorizationRequest.nonce,
                shouldAddCryptographicHolderBinding: { cnf in cnf.isEmpty == false }
            ) {
                uuidToUnsignedKBJWT[uuid] = result.unsignedJWT
                unsignedVPTokens.append(result.vpToken)
            }
        }
        
        return (vpTokenSigningPayload: uuidToUnsignedKBJWT, unsignedVPTokens: unsignedVPTokens)
    }
    
    // Note: The signed result and CredentialToCredentialQueryIdMapping map are maintained in same order thereby resulting in construction of VP successfully with correct mapping of signed KB JWT to credential query's uuid. This UUID is then used to get the relavent unsigned data using the vpTokenSigningPayload returned from this function.
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        guard let authorizationRequest = authorizationRequest as? AuthorizationDcqlRequest else {
            throw InvalidData(message: "Expected AuthorizationDcqlRequest for DCQL flow", className: Self.className)
        }
        
        var uuidToUnsignedKBJWT = [String: String]()
        var unsignedVPTokens: [UnsignedVPToken] = []
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            let uuid = UUIDGenerator.generateUUID()
            credentialToCredentialQueryIdMappings[index].identifier = uuid
            let credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            
            let matchedCredentialQuery = try authorizationRequest.dcqlQuery.credentials.first(where: { $0.id == credentialToCredentialQueryIdMapping.credentialQueryId }) ?? {
                throw InvalidData(message: "No matching credential query found for credential query id: \(credentialToCredentialQueryIdMapping.credentialQueryId)", className: Self.className)
            }()
            
            if let result = try await prepareUnsignedKeyBinding(
                credentialData: credentialToCredentialQueryIdMapping.credential,
                format: credentialToCredentialQueryIdMapping.format,
                clientId: authorizationRequest.clientId,
                nonce: authorizationRequest.nonce,
                shouldAddCryptographicHolderBinding: { cnf in
                    if matchedCredentialQuery.requireCryptographicHolderBinding {
                        if cnf.isEmpty {
                            throw InvalidData(message: "Holder binding is required for presentation but no cnf claim was present", className: Self.className)
                        }
                        return true
                    }
                    return false
                }
            ) {
                uuidToUnsignedKBJWT[uuid] = result.unsignedJWT
                unsignedVPTokens.append(result.vpToken)
            }
        }
        
        return (vpTokenSigningPayload: uuidToUnsignedKBJWT, unsignedVPTokens: unsignedVPTokens)
    }
    
    private func prepareUnsignedKeyBinding(
        credentialData: AnyCodable,
        format: FormatType,
        clientId: String,
        nonce: String,
        shouldAddCryptographicHolderBinding: ([String : Any]) throws -> Bool // Callback logic
    ) async throws -> (unsignedJWT: String, vpToken: UnsignedVPToken)? {
        let (credential, sdJWTPayload, _) = try extractSdJwtPayload(credentialData, className: Self.className)
        let confirmationKeyClaim = sdJWTPayload["cnf"] as? [String: Any] ?? [:]

        // The callback decides if we should proceed, throw, or skip
        guard try shouldAddCryptographicHolderBinding(confirmationKeyClaim) else {
            return nil
        }
        
        guard let keyId = confirmationKeyClaim["kid"] as? String else {
            throw UnsupportedOperationException(message: "Unsupported cnf format, only 'kid' is supported", className: Self.className)
        }
        let didResolver = DidPublicKeyResolver(networkManager: networkManager)
        let signingAlgorithm = try await didResolver.getJWSAlgorithm(uri: keyId)
        
        let sdHashAlgorithm = sdJWTPayload["_sd_alg"] as? String ?? HashAlgorithm.sha256.rawValue
        let sdHash = try hashData(credential, hashAlgorithm: sdHashAlgorithm, className: Self.className).toBase64UrlEncoded()

        let jwtHeader = ["alg": signingAlgorithm, "typ": keyBindingJWT]
        let jwtPayload: [String: Any] = [
            "iat": Int(Date().timeIntervalSince1970),
            "aud": clientId,
            "nonce": nonce,
            "sd_hash": sdHash
        ]

        let unsignedJWT = try JWSHandler.createUnsignedJWS(header: jwtHeader, payload: jwtPayload)
        
        let vpToken = UnsignedVPToken(
            format: format,
            holderKeyReference: keyId,
            signatureAlgorithm: signingAlgorithm,
            dataToSign: Data(unsignedJWT.utf8)
        )
        
        return (unsignedJWT, vpToken)
    }
}
