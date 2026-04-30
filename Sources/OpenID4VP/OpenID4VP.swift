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

    public init(traceabilityId: String, walletMetadata: WalletMetadata? = nil, jsonLdCanonicalizer: JsonLdCanonicalizerCallback? = nil) {
        self.traceabilityId = traceabilityId
        networkManager = NetworkManager.shared
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager, walletMetadata: walletMetadata)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
        nonceProvider = NonceProvider()
        walletNonce = nonceProvider.generateNonce()
        
        JsonLd.setCanonicalizer(jsonLdCanonicalizer)
    }

    internal init(traceabilityId: String, networkManager: NetworkManaging? = nil, walletMetadata: WalletMetadata = WalletMetadata(), nonceProvider: NonceProvider = NonceProvider(), authorizationResponseHandler: AuthorizationResponseHandler? = nil, jsonLdCanonicalizer: JsonLdCanonicalizerCallback? = nil) {
        self.networkManager = networkManager ?? NetworkManager.shared
        self.nonceProvider = nonceProvider

        self.traceabilityId = traceabilityId
        self.authorizationResponseHandler = authorizationResponseHandler ?? AuthorizationResponseHandler(networkManager: networkManager ?? NetworkManager.shared, walletMetadata: walletMetadata)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
    }

    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }
    
    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifiers: [Verifier],
        shouldValidateClient: Bool = true
    ) async throws -> AuthorizationRequest {
        // Create a new wallet nonce for each request
        walletNonce = nonceProvider.generateNonce()
        authorizationRequest = nil
        responseUri = nil
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager, walletMetadata: walletMetadata)

        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifier: trustedVerifiers,
                walletMetadata: walletMetadata,
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


    public func authenticateVerifier(
        authorizationRequest: [String: Any],
        trustedVerifiers: [Verifier],
        shouldValidateClient: Bool = true
    ) async throws -> AuthorizationRequest {
        do {
            walletNonce = nonceProvider.generateNonce()
            self.authorizationRequest = nil
            responseUri = nil
            authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager, walletMetadata: walletMetadata)

            let validatedAuthorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                authRequest: authorizationRequest,
                trustedVerifiers: trustedVerifiers,
                walletMetadata: walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                walletNonce: walletNonce,
                networkManager: networkManager
            )

            self.authorizationRequest = validatedAuthorizationRequest
            return validatedAuthorizationRequest
        } catch let error as OpenID4VPException {
            await safeSendError(error: error)
            throw error
        }
    }

    public func constructUnsignedVPToken(
        verifiableCredentials: [String: [FormatType: [AnyCodable]]],
        holderId: String? = nil,
        signatureSuite: String? = nil
    ) async throws -> [UnsignedVPToken] {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                holderId: holderId,
                signatureSuite: signatureSuite,
                walletNonce: walletNonce
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }
    
    public func constructUnsignedVPToken(
        selectedCredentials: [String: [SelectedCredential]]
    ) async throws -> [UnsignedVPToken] {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap: selectedCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                walletNonce: walletNonce
            )
        } catch {
            await safeSendError(error: error)
            throw error
        }
    }

    public func constructVPResponse(vpTokenSigningResults: [VPTokenSigningResult]) -> [String: Any] {
        do {
            return try authorizationResponseHandler.constructVPResponse(
                signingResults: vpTokenSigningResults, authorizationRequest: authorizationRequest
            )
        } catch let exception {
            return constructErrorInfo(exception: exception)
        }
    }

    public func constructErrorInfo(exception: Error) -> [String: Any] {
        return authorizationResponseHandler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: exception,
            walletNonce: walletNonce
        )
    }

    public func sendVPResponseToVerifier(
        vpTokenSigningResults: [VPTokenSigningResult]
    ) async throws -> VerifierResponse {
        do {
            return try await authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults,
                responseUri: responseUri!
            )
        } catch {
             await safeSendError(error: error)
            throw error
        }
    }

    public func sendErrorInfoToVerifier(error: Error) async throws -> VerifierResponse {
        return try await authorizationResponseHandler.sendAuthorizationError(responseUri: responseUri, authorizationRequest: authorizationRequest, error: error)
    }

    private func safeSendError(error: Error) async {
        do {
            let verifierResponse = try await sendErrorInfoToVerifier(error: error)
            (error as? OpenID4VPException)?.setVerifierResponse(verifierResponse)
        } catch {
            OpenID4VPException.error(error, className: className)
        }
    }
}
 
 
