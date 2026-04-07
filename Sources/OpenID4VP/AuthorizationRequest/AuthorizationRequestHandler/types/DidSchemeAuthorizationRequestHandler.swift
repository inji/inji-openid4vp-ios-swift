import Foundation
class DidSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(clientId: String,
                  specVersion: SpecVersion,
                  authorizationRequestParameters: [String: Any],
                  walletMetadataV2: WalletMetadataV2?,
                  walletMetadata: WalletMetadata? = nil,
                  setResponseUri: @escaping (String) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(clientId: clientId,
                   specVersion: specVersion,
                   authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadataV2: walletMetadataV2,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: DidSchemeAuthorizationRequestHandler.self)
    }
    
    func clientIdScheme() -> String {
        return ClientIdScheme.did.rawValue
    }

    func clientIdPrefix() -> String {
        return ClientIdPrefix.did.rawValue
    }
    
    func isSignedRequestSupported() -> Bool {
        return true
    }
    
    
    func isUnsignedRequestSupported() -> Bool {
        return false
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        guard let keyId = keyId else {
            throw InvalidData(message: "keyId is required to extract public key in did client_id_scheme",
                              className: className,
                              code: OpenID4VPErrorCodes.invalidRequestObject)
        }
        
        let keyResolver: PublicKeyResolver = DidPublicKeyResolver(networkManager: networkManager)
        
        return try await keyResolver.resolve(uri: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String, keyId: keyId)
    }
    
    func process(walletMetadata: WalletMetadataV2) throws -> WalletMetadataV2 {
        try validateRequestObjectSigningAlgSupported(walletMetadata, className: className)
        return walletMetadata
    }

    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata {
        if(walletMetadata.requestObjectSigningAlgValuesSupported == nil) {
            throw InvalidData(message: "request_object_signing_alg_values_supported is not present in wallet metadata.",
                              className: className)
        }
        return walletMetadata
    }
}

