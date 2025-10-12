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
    
    /// Constructs unsigned verifiable presentation (VP) tokens for the active authorization request.
    /// 
    /// Builds an unsigned VP token for each supported format using the provided verifiable credentials and the current flow state. If an error occurs, the method attempts to send an error response to the verifier and then rethrows the error.
    /// - Parameters:
    ///   - verifiableCredentials: A dictionary mapping credential identifiers to a dictionary that maps `FormatType` to an array of credential objects (`AnyCodable`) for that format.
    ///   - holderId: Optional identifier for the holder to include in the VP token.
    ///   - signatureSuite: Optional preferred signature suite to request in the VP token.
    /// - Returns: A dictionary mapping each `FormatType` to its constructed `UnsignedVPToken`.
    /// - Throws: Rethrows any error produced while constructing VP tokens.
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
    
    /// Sends the signed verifiable presentation tokens to the verifier and returns the verifier's network response.
    /// - Parameters:
    ///   - vpTokenSigningResults: A dictionary mapping each presentation format to its corresponding signing result.
    /// - Returns: The `NetworkResponse` received from the verifier after sharing the VP.
    /// - Throws: Propagates any error encountered while sharing the VP. If an error occurs, an attempt is made to send an error response to the verifier before the error is rethrown.
    public func sendAuthorizationResponseToVerifier(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) async throws -> NetworkResponse {
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
    
    /// Sends the given error to the verifier's response endpoint and returns the verifier's network response.
    /// - Parameters:
    ///   - error: The error to report to the verifier.
    /// - Returns: The `NetworkResponse` returned by the verifier.
    /// - Throws: If sending the error to the verifier fails.
    public func sendErrorResponseToVerifier(error: Error) async throws -> NetworkResponse {
       return try await authorizationResponseHandler.sendAuthorizationError(responseUri: self.responseUri, authorizationRequest: self.authorizationRequest, error: error)
    }
    
    /// Attempts to report `error` to the verifier and, if successful, attaches the verifier's network response to the error.
    /// - Parameter error: The error to send to the verifier. If `error` is an `OpenID4VPException`, its network response will be set; failures to send are recorded via `OpenID4VPException.error`.
    private func safeSendError(error: Error) async {
        do {
            let verifierResponse = try await sendErrorResponseToVerifier(error: error)
            (error as? OpenID4VPException)?.setNetworkResponse(verifierResponse)
        } catch {
            OpenID4VPException.error(error, className: className)
        }
    }
    
    /// Shares the verifiable presentation with the verifier and returns the verifier's response body.
    /// - Parameters:
    ///   - vpTokenSigningResults: A dictionary mapping each presentation format to its corresponding signing result.
    /// - Returns: The response body returned by the verifier as a `String`.
    @available(*, deprecated, renamed: "sendAuthorizationResponseToVerifier", message: "This method does not support listening to the status code sent from the verifier. Replace with sendAuthorizationResponseToVerifier(vpTokenSigningResults)")
    public func shareVerifiablePresentation(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) async throws -> String {
        return try await self.sendAuthorizationResponseToVerifier(vpTokenSigningResults: vpTokenSigningResults).body
    }
    
    /// Authenticates a verifier's authorization request and returns a validated `AuthorizationRequest`.
    /// 
    /// Generates and stores a new wallet nonce, validates the provided URL-encoded authorization request against the supplied trusted verifiers (and optional wallet metadata), and caches the resulting `authorizationRequest`.
    /// - Parameters:
    ///   - urlEncodedAuthorizationRequest: The URL-encoded authorization request received from the verifier.
    ///   - trustedVerifierJSON: An array of trusted verifier descriptors used to validate the request.
    ///   - shouldValidateClient: If `true`, perform client validation as part of request validation.
    ///   - walletMetadata: Optional wallet metadata to include in the request validation (deprecated — prefer supplying metadata via the `OpenID4VP` initializer).
    /// - Returns: A validated `AuthorizationRequest`.
    /// - Throws: Rethrows any validation or network error after attempting to send an error response to the verifier.
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
        await self.safeSendError(error: error)
    }
}