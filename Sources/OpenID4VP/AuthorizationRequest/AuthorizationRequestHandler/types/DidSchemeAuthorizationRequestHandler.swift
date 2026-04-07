import Foundation
class DidSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(clientId: String,
                  specVersion: SpecVersion,
                  authorizationRequestParameters: [String: Any],
                  walletMetadata: WalletMetadata?,
                  setResponseUri: @escaping (String) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(clientId: clientId,
                   specVersion: specVersion,
                   authorizationRequestParameters: authorizationRequestParameters,
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
        return ClientIdPrefix.decentralizedIdentifier.rawValue
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
        
        return try await keyResolver.resolve(uri: VersionLogic.of(specVersion).didUrl(clientId: clientId), keyId: keyId)
    }
    
    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata {
        try validateRequestObjectSigningAlgSupported(walletMetadata, className: className)
        return walletMetadata
    }
    
    private enum VersionLogic {
        case draft23, specV1

        static func of(_ specVersion: SpecVersion) -> VersionLogic {
            return specVersion == .draft23 ? .draft23 : .specV1
        }
        
        func didUrl(clientId: String) -> String {
            switch self {
            case .draft23:
                return clientId
            case .specV1:
                return extractClientIdPartOnly(clientId)
            }
        }
    }
}

