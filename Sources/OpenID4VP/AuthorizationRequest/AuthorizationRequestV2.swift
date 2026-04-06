import Foundation

public class AuthorizationRequestV2: Encodable {
    let clientId: String
    let responseType: String
    let responseMode: String?
    let responseUri: String?
    let redirectUri: String?
    let nonce: String
    let walletNonce: String?
    let state: String?
    
    enum CodingKeys: String, CodingKey {
        case clientId = "client_id"
        case responseType = "response_type"
        case responseMode = "response_mode"
        case responseUri = "response_uri"
        case redirectUri = "redirect_uri"
        case nonce
        case walletNonce = "wallet_nonce"
        case state
    }
    
    init(
        clientId: String,
        responseType: String,
        responseMode: String?,
        responseUri: String?,
        redirectUri: String?,
        nonce: String,
        walletNonce: String?,
        state: String?
    ) {
        self.clientId = clientId
        self.responseType = responseType
        self.responseMode = responseMode
        self.responseUri = responseUri
        self.redirectUri = redirectUri
        self.nonce = nonce
        self.walletNonce = walletNonce
        self.state = state
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clientId, forKey: .clientId)
        try container.encode(responseType, forKey: .responseType)
        try container.encodeIfPresent(responseMode, forKey: .responseMode)
        try container.encodeIfPresent(responseUri, forKey: .responseUri)
        try container.encodeIfPresent(redirectUri, forKey: .redirectUri)
        try container.encode(nonce, forKey: .nonce)
        try container.encodeIfPresent(walletNonce, forKey: .walletNonce)
        try container.encodeIfPresent(state, forKey: .state)
    }
    
    
    static func validateAndCreateAuthorizationRequest(urlEncodedAuthorizationRequest: String,
                                                      trustedVerifier: [Verifier],
                                                      walletMetadata: WalletMetadataV2,
                                                      setResponseUri: @escaping (String) -> Void,
                                                      shouldValidateClient: Bool,
                                                      walletNonce: String,
                                                      networkManager: NetworkManaging
    ) async throws -> AuthorizationRequestV2 {
        let extractedQueryParameters = try extractQueryParameters(urlEncodedAuthorizationRequest)
        
        return try await getAuthorizationRequest(authorizationRequestParameters: extractedQueryParameters,
                                                 trustedVerifiers: trustedVerifier,
                                                 walletMetadata: walletMetadata,
                                                 setResponseUri: setResponseUri,
                                                 shouldValidateClient: shouldValidateClient,
                                                 walletNonce: walletNonce,
                                                 networkManager: networkManager)
    }
    
    
    static func validateAndCreateAuthorizationRequest(
        authRequest: [String: Any],
        trustedVerifiers: [Verifier],
        walletMetadata: WalletMetadataV2,
        setResponseUri: @escaping (String) -> Void,
        shouldValidateClient: Bool,
        walletNonce: String,
        networkManager: NetworkManaging
    ) async throws -> AuthorizationRequestV2 {
        return try await getAuthorizationRequest(
            authorizationRequestParameters: authRequest,
            trustedVerifiers: trustedVerifiers,
            walletMetadata: walletMetadata,
            setResponseUri: setResponseUri,
            shouldValidateClient: shouldValidateClient,
            walletNonce: walletNonce,
            networkManager: networkManager
        )
    }
    
    private static func getAuthorizationRequest(authorizationRequestParameters: [String: Any],
                                                trustedVerifiers: [Verifier],
                                                walletMetadata: WalletMetadataV2,
                                                setResponseUri: @escaping (String) -> Void,
                                                shouldValidateClient: Bool,
                                                walletNonce: String,
                                                networkManager: NetworkManaging
    ) async throws -> AuthorizationRequestV2 {
        let authorizationRequestHandler = try getAuthorizationRequestHandlerV2(authorizationRequestParameters: authorizationRequestParameters,
                                                                               trustedVerifiers: trustedVerifiers,
                                                                               walletMetadata: walletMetadata,
                                                                               shouldValidateClient: shouldValidateClient,
                                                                               setResponseUri: setResponseUri,
                                                                               walletNonce: walletNonce,
                                                                               networkManager: networkManager)
        
        return try await authorizationRequestHandler.handle()
    }
}

public final class AuthorizationRequestDraft23: AuthorizationRequestV2 {
    var presentationDefinition: PresentationDefinition
    var clientMetadata: ClientMetadata?
    
    private enum SubCodingKeys: String, CodingKey {
        case presentationDefinition = "presentation_definition"
        case clientMetadata = "client_metadata"
    }
    
    init(
        clientId: String,
        responseType: String,
        responseMode: String?,
        responseUri: String?,
        redirectUri: String?,
        nonce: String,
        walletNonce: String?,
        state: String?,
        presentationDefinition: PresentationDefinition,
        clientMetadata: ClientMetadata?
    ) {
        self.presentationDefinition = presentationDefinition
        self.clientMetadata = clientMetadata
        super.init(
            clientId: clientId,
            responseType: responseType,
            responseMode: responseMode,
            responseUri: responseUri,
            redirectUri: redirectUri,
            nonce: nonce,
            walletNonce: walletNonce,
            state: state
        )
    }
    
    public override func encode(to encoder: Encoder) throws {
        try super.encode(to: encoder)
        var container = encoder.container(keyedBy: SubCodingKeys.self)
        try container.encode(presentationDefinition, forKey: .presentationDefinition)
        try container.encodeIfPresent(clientMetadata, forKey: .clientMetadata)
    }
}

//TODO: Enable DCQL query when DCQL is supported
public final class AuthorizationRequestSpecVersion1: AuthorizationRequestV2 {
    //    var dcqlQuery: DCQLQuery
    var clientMetadata: ClientMetadataV2?
    
    private enum SubCodingKeys: String, CodingKey {
        case dcqlQuery = "dcql_query"
        case clientMetadata = "client_metadata"
    }
    
    init(
        clientId: String,
        responseType: String,
        responseMode: String?,
        responseUri: String?,
        redirectUri: String?,
        nonce: String,
        walletNonce: String?,
        state: String?,
        //        dcqlQuery: DCQLQuery,
        clientMetadata: ClientMetadataV2?
    ) {
        //        self.dcqlQuery = dcqlQuery
        self.clientMetadata = clientMetadata
        super.init(
            clientId: clientId,
            responseType: responseType,
            responseMode: responseMode,
            responseUri: responseUri,
            redirectUri: redirectUri,
            nonce: nonce,
            walletNonce: walletNonce,
            state: state
        )
    }
    
    public override func encode(to encoder: Encoder) throws {
        try super.encode(to: encoder)
        var container = encoder.container(keyedBy: SubCodingKeys.self)
        //        try container.encode(dcqlQuery, forKey: .dcqlQuery)
        try container.encodeIfPresent(clientMetadata, forKey: .clientMetadata)
    }
}
