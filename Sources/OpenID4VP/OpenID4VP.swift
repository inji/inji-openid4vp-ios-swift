import Foundation

public class OpenID4VP {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest!
    private var responseUri: String?
    private var authorizationResponseHandler: AuthorizationResponseHandler
    private let walletMetadata: WalletMetadata?
    private var walletNonce: String = ""
    private let nonceProvider: NonceProvider
    
    private let className = String(describing: type(of: OpenID4VP.self))
    
    public init(traceabilityId: String, walletMetadata: WalletMetadata? = nil) {
        self.traceabilityId = traceabilityId
        self.networkManager = NetworkManager.shared
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: self.networkManager)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
        nonceProvider = NonceProvider()
    }
    
    internal init(traceabilityId: String, networkManager: NetworkManaging? = nil, walletMetadata: WalletMetadata? = nil, nonceProvider: NonceProvider = NonceProvider()) {
        self.networkManager = networkManager ?? NetworkManager.shared
        self.nonceProvider = nonceProvider
        
        self.traceabilityId = traceabilityId
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: self.networkManager)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
    }
    
    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }
    
    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifierJSON: [Verifier],
        shouldValidateClient: Bool = true
    ) async throws -> AuthorizationRequest {
        // Create a new wallet nonce for each request
        self.walletNonce = nonceProvider.generateNonce()
        self.authorizationRequest = nil
        self.responseUri = nil
        self.authorizationResponseHandler = AuthorizationResponseHandler(networkManager: self.networkManager)
        
        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifierJSON: trustedVerifierJSON,
                walletMetadata: self.walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                walletNonce: walletNonce,
                networkManager: networkManager
            )
            return authorizationRequest
        } catch let exception {
            await safeSendError(error: exception)
            throw exception
        }
    }
    
    public func constructUnsignedVPToken(
        verifiableCredentials: [String: [FormatType: [AnyCodable]]],
        holderId: String? = nil,
        signatureSuite: String? = nil
    ) async throws -> [FormatType: UnsignedVPToken] {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                holderId: holderId,
                signatureSuite: signatureSuite,
                walletNonce: self.walletNonce
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }
    
    public func shareVerifiablePresentation(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) async throws -> String {
        do {
            return try await authorizationResponseHandler.shareVP(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults,
                responseUri: responseUri!
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }
    
    public func sendErrorResponseToVerifier(error: Error) async throws -> String {
       return try await authorizationResponseHandler.sendAuthorizationError(responseUri: self.responseUri, authorizationRequest: self.authorizationRequest, error: error)
    }
    
    private func safeSendError(error: Error) async {
        do {
            let verifierResponse = try await sendErrorResponseToVerifier(error: error)
            (error as? OpenID4VPException)?.setNetworkResponse(verifierResponse)
        } catch {
            OpenID4VPException.error(error, className: className)
        }
    }
    
    @available(*, deprecated, message: "Use authenticateVerifier without WalletMetadata instead. Reason: WalletMetadata is moved to OpenID4VP constructor instead of being passed as parameter")
    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifierJSON: [Verifier],
        shouldValidateClient: Bool = false,
        walletMetadata: WalletMetadata? = nil
    ) async throws -> AuthorizationRequest {
        // Create a new wallet nonce for each request
        self.walletNonce = nonceProvider.generateNonce()
        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifierJSON: trustedVerifierJSON,
                walletMetadata: walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                walletNonce: walletNonce,
                networkManager: networkManager
            )
            return authorizationRequest
        } catch let exception {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }
    
    @available(*, deprecated, message: "Use constructUnsignedVPToken with [String: [FormatType: [Any]]] instead")
    public func constructVerifiablePresentationToken(
        verifiableCredentials: [String: [String]]
    ) async throws -> String {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPTokenV1(
                verifiableCredentials: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                walletNonce: self.walletNonce
            )
        } catch {
            await sendErrorToVerifier(error: error)
            throw error
        }
    }
    
    @available(*, deprecated, message: "Supports only direct POST response mode for LDP VC. Use shareVerifiablePresentation with VPTokenSigningResults instead")
    public func shareVerifiablePresentation(
        vpResponseMetadata: VPResponseMetadata
    ) async throws -> String {
        do {
            return try await authorizationResponseHandler.shareVPV1(
                vpResponseMetadata: vpResponseMetadata,
                nonce: authorizationRequest.nonce,
                state: authorizationRequest.state,
                responseUri: responseUri!, presentationDefinitionId: authorizationRequest.presentationDefinition.id
            )
        } catch {
            await sendErrorToVerifier(error: error)
            throw error
        }
    }
    
    @available(*, deprecated, renamed: "sendErrorResponseToVerifier", message: "sendErrorToVerifier is now changed to sendErrorResponseToVerifier. Reason: This does not support listening the response from the verifier")
    public func sendErrorToVerifier(error: Error) async {
        do {
            _ = try await authorizationResponseHandler.sendAuthorizationError(responseUri: self.responseUri, authorizationRequest: self.authorizationRequest, error: error)
        } catch {
            OpenID4VPException.error(error, className: String(describing: type(of: self)))
        }
    }
}
