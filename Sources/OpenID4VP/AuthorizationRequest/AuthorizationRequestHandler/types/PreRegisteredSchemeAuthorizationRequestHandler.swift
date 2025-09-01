import Foundation
import JSONWebKey

class PreRegisteredSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    let trustedVerifiers: [Verifier]
    let shouldValidateClient: Bool
    
    init(trustedVerifiers: [Verifier],
         authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata?,
         shouldValidateClient: Bool,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging) {
        self.trustedVerifiers = trustedVerifiers
        self.shouldValidateClient = shouldValidateClient
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: PreRegisteredSchemeAuthorizationRequestHandler.self)
    }
    
    func clientIdScheme() -> String {
        return ClientIdScheme.preRegistered.rawValue
    }
    
    override func validateClientId() throws {
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String }) else {
                throw InvalidVerifier(message: "Verifier is not trusted by the wallet", className: AuthorizationRequest.className)
            }
        }
    }
    
    func process(walletMetadata: WalletMetadata) -> WalletMetadata {
        var updatedWalletMetadata = walletMetadata
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        return updatedWalletMetadata
    }
    
    func isRequestUriSupported() -> Bool {
        return true
    }
    
    
    func isRequestObjectSupported() -> Bool {
        return true
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        let clientId = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String
        
        if ((authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata.rawValue]) != nil)  {
            throw InvalidData(
                message: "client_metadata available in Authorization Request, cannot be used to verify the signed Authorization Request",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequestObject
            )
        }
        
        if let preRegisteredClient = trustedVerifiers.filter({ $0.clientId == clientId }).first {
            if let publicKeys = preRegisteredClient.clientMetadata?.jwks {
                return try filterAndExtractKey(jwks: publicKeys, keyId: keyId, algorithm: algorithm)
            } else {
                throw InvalidData(
                    message: "jwks not available in pre-registered client_metadata to verify the signed Authorization Request",
                    className: className,
                    code: OpenID4VPErrorCodes.invalidRequestObject
                )
            }
            
        }
        throw PublicKeyResolutionFailed(message: "Public key extraction failed for keyId = \(keyId ?? "null"), algorithm: \(algorithm)",
                                        className: className,
                                        code: OpenID4VPErrorCodes.invalidRequestObject)
    }
    
    override func validateAndParseRequestFields() async throws {
        if shouldValidateClient {
            let clientId = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String
            if let preRegisteredClient = trustedVerifiers.filter({ $0.clientId == clientId }).first {
                let responseUri = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]) ?? "null"
                guard preRegisteredClient.responseUris.contains(responseUri) else {
                    throw InvalidVerifier(
                        message: "response_uri trust cannot be established",
                        className: AuthorizationRequest.className
                    )
                }
                if(preRegisteredClient.clientMetadata != nil) {
                    if (authorizationRequestParameters.keys.contains(AuthorizationRequestFieldConstants.clientMetadata.rawValue)){
                        throw InvalidVerifier(
                            message: "client_metadata provided despite pre-registered metadata already existing for the Client Identifier.",
                            className: AuthorizationRequest.className
                        )
                    }
                    
                    
                    // Update client_metadata in authorizationRequestParameters from the registered client for further use
                    authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata.rawValue] = preRegisteredClient.clientMetadata
                }
            }
        }
        try await super.validateAndParseRequestFields()
    }
    
    private func filterAndExtractKey(jwks publicKeys: JWKSet, keyId: String?, algorithm: String) throws -> PublicKeyType {
        // if kid is available filter using it
        if(keyId != nil) {
            if let keyDict = (publicKeys.keys as [JWK]).filter({ $0.keyID == keyId }).first {
                return try jwkToPublicKey(keyDict, className: className)
            } else {
                throw PublicKeyResolutionFailed(message: "Public key extraction failed for kid: \(String(describing: keyId))",
                                                className: className,
                                                code: OpenID4VPErrorCodes.invalidRequestObject)
            }
        }
        
        // else filter using algorithm
        let keyDict = (publicKeys.keys as [JWK]).filter({ $0.algorithm == algorithm && $0.publicKeyUse == .signature })
        if(keyDict.count == 1) {
            return try jwkToPublicKey(keyDict[0], className: className)
        } else if (keyDict.count > 1) {
            // filter using the key usage
            let matchingKeys = (keyDict).filter({ $0.publicKeyUse == .signature })
            if(matchingKeys.count == 1) {
                return try jwkToPublicKey(matchingKeys[0], className: className)
            } else if (matchingKeys.count == 0) {
                throw PublicKeyResolutionFailed(message: "No public key found for algorithm: \(algorithm) with key use: signature",
                                                className: className,
                                                code: OpenID4VPErrorCodes.invalidRequestObject)
            }else {
                throw PublicKeyResolutionFailed(message: "Multiple public keys found for algorithm: \(algorithm)",
                                                className: className,
                                                code: OpenID4VPErrorCodes.invalidRequestObject)
            }
        }
        else {
            throw PublicKeyResolutionFailed(message: "Public key extraction failed for algorithm: \(algorithm)",
                                            className: className,
                                            code: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
}
