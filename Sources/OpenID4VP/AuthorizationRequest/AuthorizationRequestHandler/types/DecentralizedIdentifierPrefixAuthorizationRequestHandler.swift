import Foundation
class DecentralizedIdentifierPrefixAuthorizationRequestHandler:  ClientIdPrefixBasedAuthorizationRequestHandler {
    override init(clientId: String,
                  specVersion: SpecVersion,
                  authorizationRequestParameters: [String: Any],
                  walletConfig: WalletConfig,
                  setResponseUri: @escaping (String) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(clientId: clientId,
                   specVersion: specVersion,
                   authorizationRequestParameters: authorizationRequestParameters,
                   walletConfig: walletConfig,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: DecentralizedIdentifierPrefixAuthorizationRequestHandler.self)
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
            throw InvalidData(message: "keyId is required to extract public key in \(clientIdPrefix()) client_id_prefix",
                              className: className,
                              code: OpenID4VPErrorCodes.invalidRequestObject)
        }
        
        let keyResolver: PublicKeyResolver = DidPublicKeyResolver(networkManager: networkManager)
        
        return try await keyResolver.resolve(uri: SpecVersionHandler.of(specVersion).didUrl(clientId: clientId), keyId: keyId)
    }
    
    func getWalletMetadata(walletConfig: WalletConfig) throws -> [String: Any] {
        try validateRequestObjectSigningAlgSupported(walletConfig, className: className)
        return try walletConfig.toWalletMetadata(specVersion: specVersion)
    }
    
    private enum SpecVersionHandler {
        case draft23, specV1

        static func of(_ specVersion: SpecVersion) -> SpecVersionHandler {
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

