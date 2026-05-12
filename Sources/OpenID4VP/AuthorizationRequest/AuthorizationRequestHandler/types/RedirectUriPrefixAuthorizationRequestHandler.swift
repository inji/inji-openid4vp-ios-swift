import Foundation
class RedirectUriPrefixAuthorizationRequestHandler:  ClientIdPrefixBasedAuthorizationRequestHandler {
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
        super.className = String(describing: RedirectUriPrefixAuthorizationRequestHandler.self)
    }
    
    func clientIdPrefix() -> String {
        return ClientIdPrefix.redirectUri.rawValue
    }
    
    func isSignedRequestSupported() -> Bool {
        return false
    }
    
    func isUnsignedRequestSupported() -> Bool {
        return true
    }
    
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType {
        throw UnsupportedOperationException(message: "Public key extraction is not supported for redirect_uri client_id_prefix", className: className)
    }
    
    func getWalletMetadata(walletConfig: WalletConfig) throws -> [String: Any] {
        return try walletConfig.toWalletMetadata(specVersion: specVersion, excludeSignedRequestConfig: true)
    }

    override func validateAndParseRequestFields()async throws {
        try await super.validateAndParseRequestFields()
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        switch responseMode {
        case ResponseMode.directPost.rawValue, ResponseMode.directPostJwt.rawValue:
            try validateUriCombinations(authorizationRequestParameters: authorizationRequestParameters, validAttribute: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidAttribute: AuthorizationRequestFieldConstants.redirectUri.rawValue)
            break
        case ResponseMode.iarPost.rawValue, ResponseMode.iarPostJwt.rawValue:
            print("IAR_POST or IAR_POST_JWT response_mode is used")
        default:
            throw InvalidResponseMode(
                message : "Given response_mode \(String(describing: responseMode)) is not supported",
                className: className
            )
        }
        
    }
    
    private func validateUriCombinations(authorizationRequestParameters: [String: Any], validAttribute: String, inValidAttribute: String) throws {
        if authorizationRequestParameters.keys.contains(inValidAttribute) {
            throw InvalidData(message: "\(inValidAttribute) should not be present for given response_mode", className: className)
        } else {
            try validateAttribute(validAttribute, values: self.authorizationRequestParameters)
        }
        
        let validValue = authorizationRequestParameters[validAttribute]
        let clientIdValue = extractClientIdPartOnly(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? "")
        
        if validValue as? String != clientIdValue {
            throw InvalidData(
                message: "\(validAttribute) should be equal to client_id for given client_id_prefix",
                className: className
            )
        }
    }
    
}
