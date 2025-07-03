import Foundation

public class OpenID4VP {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest!
    private var responseUri: String?
    private var authorizationResponseHandler: AuthorizationResponseHandler
    private let walletMetadata: WalletMetadata?
    

    public init(traceabilityId: String, networkManager: NetworkManaging? = nil, walletMetadata: WalletMetadata? = nil) {
        self.traceabilityId = traceabilityId
        self.networkManager = networkManager ?? NetworkManager.shared
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: self.networkManager)
        self.walletMetadata = walletMetadata
    }

    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }

    public func authenticateVerifier(
        urlEncodedAuthorizationRequest: String,
        trustedVerifierJSON: [Verifier],
        shouldValidateClient: Bool = true
    ) async throws -> AuthorizationRequest {
        Logger.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)

        do {
            authorizationRequest = try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifierJSON: trustedVerifierJSON,
                walletMetadata: self.walletMetadata,
                setResponseUri: setResponseUri,
                shouldValidateClient: shouldValidateClient,
                networkManager: networkManager
            )
            return authorizationRequest
        } catch let exception {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }

    public func constructUnsignedVPToken(
        verifiableCredentials: [String: [FormatType: [AnyCodable]]],
        holderId: String,
        signatureSuite: String
    ) async throws -> [FormatType: UnsignedVPToken] {
        do {
            return try authorizationResponseHandler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!,
                holderId: holderId,
                signatureSuite: signatureSuite
            )
        } catch {
            await sendErrorToVerifier(error: error)
            throw error
        }
    }

    @available(*, deprecated, message: "Use constructUnsignedVPToken with [String: [FormatType: [Any]]] instead")
    public func constructVerifiablePresentationToken(
        verifiableCredentials: [String: [String]]
    ) async throws -> String {
        do {
            return try authorizationResponseHandler.constructUnsignedVPTokenV1(
                verifiableCredentials: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri!
            )
        } catch {
            await sendErrorToVerifier(error: error)
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
            await sendErrorToVerifier(error: error)
            throw error
        }
    }

    @available(*, deprecated, message: "Use shareVerifiablePresentation with VPTokenSigningResult instead")
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
    

    public func sendErrorToVerifier(error: Error) async {
        let logTag = Logger.getLogTag(String(describing: OpenID4VP.self))

        
        var errorInfo: [String: String] = [
            "traceabilityId": "\(traceabilityId)"
        ]

        let resolvedError: OpenID4VPException
        if let openidError = error as? OpenID4VPException {
            resolvedError = openidError
        } else {
            resolvedError = GenericFailure(
                message: "\(error)",
                className: String(describing: OpenID4VP.self)
            )
        }

        errorInfo.merge(resolvedError.toErrorResponse()) { _, new in new }

        do {
            _ = try await networkManager.sendHTTPRequest(
                url: responseUri ?? "",
                method: .post,
                bodyParams: errorInfo,
                headers: ["Content_Type": ContentTypes.applicationFormUrlEncoded.rawValue]
            )
        } catch {
            Logger.error(logTag, NetworkRequestException.invalidResponse(
                message: "Unexpected error occurred while sending the error to verifier: \(error)"
            ))
        }
    }
}
