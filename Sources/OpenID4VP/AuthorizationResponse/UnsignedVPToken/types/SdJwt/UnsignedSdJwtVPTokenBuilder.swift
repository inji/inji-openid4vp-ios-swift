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
            let (credential, sdJWTPayload, _) = try extractSdJwtPayload(credentialInputDescriptorMapping.credential, className: Self.className)
            
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

            let (kid, alg) = try await resolveSdJwtKeyAndAlg(credential)
            unsignedVPTokens.append(UnsignedVPToken(
                format: credentialInputDescriptorMapping.format,
                holderKeyReference: kid,
                signatureAlgorithm: alg,
                dataToSign: unsignedJWT
            ))
        }
        
        return (
            vpTokenSigningPayload: uuidToUnsignedKBJWT,
            unsignedVPTokens: unsignedVPTokens
        )
    }
    
    // Note: The signed result and CredentialToCredentialQueryIdMapping map are maintained in same order thereby resulting in construction of VP successfully with correct mapping of signed KB JWT to credential query's uuid. This UUID is then used to get the relavent unsigned data using the vpTokenSigningPayload returned from this function.
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        guard let authorizationRequest = authorizationRequest as? AuthorizationDcqlRequest else {
            throw InvalidData(message: "Expected AuthorizationDcqlRequest for DCQL flow", className: Self.className)
        }
        
        var uuidToUnsignedKBJWT = [String: String]()
        var unsignedVPTokens: [UnsignedVPToken] = []
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            var credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            let uuid = UUIDGenerator.generateUUID()

            credentialToCredentialQueryIdMapping.identifier = uuid
            credentialToCredentialQueryIdMappings[index] = credentialToCredentialQueryIdMapping
            
            let (credentialData, credentialQueryId) = (credentialToCredentialQueryIdMapping.credential, credentialToCredentialQueryIdMapping.credentialQueryId)
            
            let mappedCredentialQuery = try authorizationRequest.dcqlQuery.credentials.first(where: { $0.id == credentialQueryId }) ?? {
                throw InvalidData(message: "No matching credential query found for credential query id: \(credentialQueryId)", className: Self.className)
            }()
            
            let (credential, sdJWTPayload, _) = try extractSdJwtPayload(credentialData, className: Self.className)
            
            if(mappedCredentialQuery.requireCryptographicHolderBinding) {
                guard let confirmationKeyClaim = sdJWTPayload["cnf"] as? [String: Any], !confirmationKeyClaim.isEmpty else {
                    throw InvalidData(message: "Holder binding is required but no cnf claim was present", className: Self.className)
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
                
                // Unsigned Tokens are generated  only for holder binding required credentials
                unsignedVPTokens.append(UnsignedVPToken(
                    format: credentialToCredentialQueryIdMapping.format,
                    holderKeyReference: confirmationKeyClaim["kid"] as! String,
                    signatureAlgorithm: jwtSigningALgorithm,
                    dataToSign: unsignedJWT
                ))
            } else {
                // In case of holder binding not required, continue
                continue
            }
        }
        
        return (
            vpTokenSigningPayload: uuidToUnsignedKBJWT,
            unsignedVPTokens: unsignedVPTokens
        )
    }
}
