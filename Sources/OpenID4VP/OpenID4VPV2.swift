import Foundation

public class OpenID4VPV2 {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequestV2!
    private var responseUri: String?
    private var authorizationResponseHandler: AuthorizationResponseHandler
    private let walletMetadata: WalletMetadataV2
    private var walletNonce: String = ""
    private let nonceProvider: NonceProvider

    private let className = String(describing: type(of: OpenID4VP.self))

    public init(traceabilityId: String, walletMetadata: WalletMetadataV2 = WalletMetadataV2()) {
        self.traceabilityId = traceabilityId
        networkManager = NetworkManager.shared
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
        nonceProvider = NonceProvider()
        walletNonce = nonceProvider.generateNonce()
    }

    internal init(traceabilityId: String, networkManager: NetworkManaging? = nil, walletMetadata: WalletMetadataV2 = WalletMetadataV2(), nonceProvider: NonceProvider = NonceProvider(), authorizationResponseHandler: AuthorizationResponseHandler? = nil) {
        self.networkManager = networkManager ?? NetworkManager.shared
        self.nonceProvider = nonceProvider

        self.traceabilityId = traceabilityId
        self.authorizationResponseHandler = authorizationResponseHandler ?? AuthorizationResponseHandler(networkManager: networkManager ?? NetworkManager.shared)
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
    ) async throws -> AuthorizationRequestV2 {
        // Create a new wallet nonce for each request
        walletNonce = nonceProvider.generateNonce()
        authorizationRequest = nil
        responseUri = nil
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager)

        do {
            authorizationRequest = try await AuthorizationRequestV2.validateAndCreateAuthorizationRequest(
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
//            TODO: uncomment safe send error
//            await safeSendError(error: exception)
            throw exception
        }
    }

    public func constructUnsignedVPToken(
        verifiableCredentials: [String: [FormatType: [AnyCodable]]],
        holderId: String? = nil,
        signatureSuite: String? = nil
    ) async throws -> [UnsignedVPTokenV2] {
        do {
            return try await authorizationResponseHandler.constructUnsignedVPTokenV3(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                holderId: holderId,
                signatureSuite: signatureSuite,
                walletNonce: walletNonce
            )
        } catch {
//            TODO: uncomment safe send error
//            await safeSendError(error: error)
            throw error
        }
    }
    
    // public func sendVPResponseToVerifier(
    //     vpTokenSigningResults: [VPTokenSigningResultV2]
    // ) async throws -> VerifierResponse {
    //     do {
    //         return try await authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
    //             authorizationRequest: authorizationRequest,
    //             vpTokenSigningResults: vpTokenSigningResults,
    //             responseUri: responseUri!
    //         )
    //     } catch {
    //         await safeSendError(error: error)
    //         throw error
    //     }
    // }
}
