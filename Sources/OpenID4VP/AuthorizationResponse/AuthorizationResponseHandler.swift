
import Foundation

public class AuthorizationResponseHandler {
    private let networkManager: NetworkManaging
    private var walletNonce: String = ""
    private var signatureSuite: String = SignatureAlgorithm.ed25519Signature2020.rawValue
    private var formatToCredentialInputDescriptorMapping: [FormatType: [CredentialInputDescriptorMapping]] = [:]
    private var unsignedVPTokenResults: [FormatType: (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken)] = [:]
    private var specVersion: SpecVersion = .v1
    private let walletMetadata: WalletMetadata?

    public static let className = String(describing: AuthorizationResponseHandler.self)

    public init(networkManager: NetworkManaging, walletMetadata: WalletMetadata? = nil) {
        self.networkManager = networkManager
        self.walletMetadata = walletMetadata
    }
    
    func constructUnsignedVPToken(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String?,
        signatureSuite: String?,
        walletNonce: String
    ) async throws -> [UnsignedVPTokenV2] {

        if authorizationRequest as? AuthorizationPresentationExchangeRequest != nil {
            self.specVersion = .draft23
        }
        
        let hasLdpVc = credentialsMap.values.contains { formatMap in
            formatMap.keys.contains(.ldp_vc)
        }
        if hasLdpVc {
            // In case of ldp_vc, the Verifiable presentation created will have the info of holder and signature suite
            if isNullOrEmpty(holderId) {
                throw InvalidData(
                    message: "Holder ID cannot be null or empty for LDP VC format",
                    className: AuthorizationResponseHandler.className
                )
            }
            if isNullOrEmpty(signatureSuite) {
                throw InvalidData(
                    message: "Signature Suite cannot be null or empty for LDP VC format",
                    className: AuthorizationResponseHandler.className
                )
            }
        }
        self.signatureSuite = signatureSuite ?? self.signatureSuite
        
        return try await SpecVersionHandler.from(authorizationRequest).createUnsignedVPToken(credentialsMap: credentialsMap, authorizationRequest: authorizationRequest, holderId: holderId, signatureSuite: signatureSuite, walletNonce: walletNonce, handler: self)
    }
    
    func constructUnsignedVPToken(
        credentialsMap: [String: [AnyCodable]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        walletNonce: String
    ) async throws -> [UnsignedVPTokenV2] {
        if authorizationRequest as? AuthorizationPresentationExchangeRequest != nil {
            self.specVersion = .draft23
        }
        
        return []
    }

    func constructVPResponse(
        signingResults: [VPTokenSigningResultV2],
        authorizationRequest: AuthorizationRequest
    ) throws -> [String: String] {

        let reconstructed = try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            formatMappings: formatToCredentialInputDescriptorMapping,
            signingResults: signingResults,
            signatureSuite: self.signatureSuite
        )

        return try constructAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: reconstructed
        )
    }
    
    func sendAuthorizationError(responseUri: String?, authorizationRequest: AuthorizationRequest?, error: Error) async throws -> VerifierResponse {
        guard let responseUri = responseUri, !responseUri.isEmpty else {
            throw ErrorDispatchFailure(message: "Response URI is not set. Cannot send error to verifier.", className: Self.className)
        }

        var errorPayload: [String: String] = [:]

        let resolvedError: OpenID4VPException
        if let openidError = error as? OpenID4VPException {
            resolvedError = openidError
        } else {
            resolvedError = GenericFailure(
                message: "\(error)",
                className: String(describing: OpenID4VP.self)
            )
        }

        errorPayload.merge(resolvedError.toErrorResponse()) { _, new in new }

        if let state = authorizationRequest?.state, !state.isEmpty {
            errorPayload["state"] = state
        }

        do {
            let dispatchResult = try await networkManager.sendHTTPRequest(
                url: responseUri,
                method: .post,
                bodyParams: errorPayload,
                headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue]
            )
            let verifierResponse: VerifierResponse = toVerifierResponse(dispatchResult)

            (error as? OpenID4VPException)?.setVerifierResponse(verifierResponse)
            return verifierResponse
        } catch {
            throw ErrorDispatchFailure(
                message: "Failed to send error to verifier: \(error)",
                className: Self.className
            )
        }
    }
    
    func constructAndSendAuthorizationResponseToVerifier(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [VPTokenSigningResultV2],
        responseUri: String
    ) async throws -> VerifierResponse {
        let reconstructedVpTokenSigningResult : [FormatType : VPTokenSigningResult] = try constructSigningResults(
            unsignedVPTokenResults: unsignedVPTokenResults,
            formatMappings: formatToCredentialInputDescriptorMapping,
            signingResults: vpTokenSigningResults,
            signatureSuite: self.signatureSuite
        )

        let authorizationResponse = try createAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: reconstructedVpTokenSigningResult
        )

        let response: NetworkResponse = try await sendAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            authorizationResponse: authorizationResponse,
            responseUri: responseUri
        )
        return toVerifierResponse(response)
    }
    
    private func createUnsignedVPToken(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        walletNonce: String,
        holderId: String?,
        signatureSuite: String?
    ) async throws -> [FormatType: UnsignedVPToken] {
        if credentialsMap.isEmpty {
            throw InvalidData(
                message: "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
                className: AuthorizationResponseHandler.className
            )
        }

        self.walletNonce = walletNonce

        unsignedVPTokenResults = try await createUnsignedVPTokens(
            credentialsMap: credentialsMap,
            authorizationRequest: authorizationRequest,
            holderId: holderId,
            signatureSuite: signatureSuite
        )

        let unsignedVPTokensExtracted: [FormatType: UnsignedVPToken] = unsignedVPTokenResults.mapValues { innerMap in
            innerMap.1
        }

        return unsignedVPTokensExtracted
    }
    
    private func constructAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) throws -> [String: String] {
        let authorizationResponse = try createAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults
        )

        return try ResponseModeBasedHandlerFactory
            .get(responseMode: authorizationRequest.responseMode)
            .getAuthorizationResponse(
                authorizationRequest: authorizationRequest,
                authorizationResponse: authorizationResponse,
                walletNonce: walletNonce,
                walletMetadata: walletMetadata
            )
    }

    func constructAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        exception: Error,
        walletNonce: String
    ) -> [String: Any] {
        self.walletNonce = walletNonce
        
        let authorizationResponse: AuthorizationErrorResponse

        if let openIDException = exception as? OpenID4VPException {
            authorizationResponse = openIDException.toAuthorizationErrorResponse(state: authorizationRequest?.state)
        } else {
            let genericException = GenericFailure(
                message: exception.localizedDescription.isEmpty ? "Unknown internal error" : exception.localizedDescription,
                className: String(describing: OpenID4VP.self)
            )
            authorizationResponse = genericException.toAuthorizationErrorResponse(state: authorizationRequest?.state)
        }
 
        do {
            return try ResponseModeBasedHandlerFactory
                .get(responseMode: authorizationRequest?.responseMode ?? ResponseMode.directPost.rawValue)
                .getAuthorizationErrorResponse(
                    authorizationRequest: authorizationRequest,
                    authorizationResponse: authorizationResponse,
                    walletNonce: self.walletNonce
                )
        } catch {
            OpenID4VPException.error(error, className: Self.className)
            return [
                "error": "invalid_request",
                "error_description": "Failed to construct error response: \(error.localizedDescription)"
            ]
        }
    }
    
    private func createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) throws -> AuthorizationResponse {
        switch authorizationRequest.responseType {
        case ResponseType.vp_token.rawValue:
            return try SpecVersionHandler.from(authorizationRequest).createVPTokenResponse(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults,
                unsignedVPTokenResults: unsignedVPTokenResults,
                formatToCredentialInputDescriptorMapping: formatToCredentialInputDescriptorMapping,
                handler: self
            )
        default:
            throw InvalidData(
                message: "Provided response_type - \(authorizationRequest.responseType) is not supported",
                className: AuthorizationResponseHandler.className
            )
        }
    }
    
    private func createVPTokenAndPresentationSubmission(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult],
        authorizationRequest: AuthorizationRequest,
        unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)],
        formatToCredentialInputDescriptorMapping: [FormatType: [CredentialInputDescriptorMapping]]
    ) throws -> (VPTokenType, PresentationSubmission) {
        if Set(unsignedVPTokenResults.keys) != Set(vpTokenSigningResults.keys) {
            throw InvalidData(
                message: "VPTokenSigningResult not provided for the required formats",
                className: Self.className
            )
        }

        var finalVpTokens: [VPToken] = []
        var finalDescriptorMappings: [DescriptorMap] = []
        var rootIndex = 0

        for (credentialFormat, credentialInputDescriptorMappings) in formatToCredentialInputDescriptorMapping {
            guard let vpTokenSigningResult = vpTokenSigningResults[credentialFormat] else {
                throw InvalidData(
                    message: "unable to find the related credential format - \(credentialFormat) in the vpTokenSigningResults map",
                    className: Self.className
                )
            }
            guard let unsignedVPTokenResult = unsignedVPTokenResults[credentialFormat] else {
                throw InvalidData(
                    message: "unable to find the related credential format - \(credentialFormat) in the unsignedVPTokenResults map",
                    className: Self.className
                )
            }

            let vpTokenBuilder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: credentialFormat)

            let (vpTokens, descriptorMaps, nextRootIndex) = try vpTokenBuilder.build(
                credentialInputDescriptorMappings: credentialInputDescriptorMappings,
                unsignedVPTokenResult: unsignedVPTokenResult,
                vpTokenSigningResult: vpTokenSigningResult,
                rootIndex: rootIndex
            )
            finalVpTokens.append(contentsOf: vpTokens)
            finalDescriptorMappings.append(contentsOf: descriptorMaps)
            rootIndex = nextRootIndex
        }

        let vpToken: VPTokenType = (finalVpTokens.count == 1)
            ? .vpTokenElement(finalVpTokens[0])
            : .vpTokenArray(finalVpTokens)

        sanitizeDescriptorMap(&finalDescriptorMappings, isSingleVPToken: finalVpTokens.count == 1)
        let presentationSubmission = PresentationSubmission(
            definitionId: SpecVersionHandler.from(authorizationRequest).getPresentationDefinitionId(authorizationRequest),
            descriptorMap: finalDescriptorMappings
        )

        return (vpToken, presentationSubmission)
    }

    private func sanitizeDescriptorMap(
        _ descriptorMaps: inout [DescriptorMap],
        isSingleVPToken: Bool
    ) {
        // In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        // and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        if isSingleVPToken {
            for i in 0 ..< descriptorMaps.count {
                let updatedRootPath = descriptorMaps[i].path.replacingOccurrences(of: #"\[\d+]"#, with: "", options: .regularExpression)
                descriptorMaps[i] = DescriptorMap(
                    id: descriptorMaps[i].id,
                    format: descriptorMaps[i].format,
                    path: updatedRootPath,
                    pathNested: descriptorMaps[i].pathNested
                )
            }
        }
    }
    
    private func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        responseUri: String
    ) async throws -> NetworkResponse {
        return try await ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode)
            .sendAuthorizationResponse(
                authorizationRequest: authorizationRequest,
                authorizationResponse: authorizationResponse,
                url: responseUri,
                networkManager: networkManager,
                producerInfo: walletNonce,
                recipientInfo: authorizationRequest.nonce,
                walletMetadata: walletMetadata
            )
    }

    private func createUnsignedVPTokens(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        holderId: String?,
        signatureSuite: String?
    ) async throws -> [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)] {
        createFormatToCredentialInputDescriptorMapping(matchingCredentials: credentialsMap)

        var unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)] = [:]
        let specVersion: SpecVersion = authorizationRequest is AuthorizationPresentationExchangeRequest ? .draft23 : .v1

        for format in formatToCredentialInputDescriptorMapping.keys {
            guard var credentialsArray = formatToCredentialInputDescriptorMapping[format] else {
                continue
            }
            switch format {
            case .ldp_vc:
                let token = try await UnsignedLdpVPTokenBuilder(
                    authorizationRequest: authorizationRequest,
                    specVersion: specVersion,
                    id: UUIDGenerator.generateUUID(),
                    holder: holderId ?? "",
                    signatureSuite: signatureSuite ?? "Ed25519Signature2020",
                    walletMetadata: walletMetadata
                ).build(credentialInputDescriptorMappings: &credentialsArray)
                unsignedVPTokenResults[format] = token
            case .mso_mdoc:
                let token = try await UnsignedMdocVPTokenBuilder(
                    authorizationRequest: authorizationRequest,
                    specVersion: specVersion,
                    mdocGeneratedNonce: walletNonce,
                    walletMetadata: walletMetadata
                ).build(credentialInputDescriptorMappings: &credentialsArray)
                unsignedVPTokenResults[format] = token
            case .dc_sd_jwt, .vc_sd_jwt:
                let token = try await UnsignedSdJwtVPTokenBuilder(
                    authorizationRequest: authorizationRequest,
                    specVersion: specVersion,
                    walletMetadata: walletMetadata
                ).build(credentialInputDescriptorMappings: &credentialsArray)
                unsignedVPTokenResults[format] = token
            }
            formatToCredentialInputDescriptorMapping[format] = credentialsArray
        }

        return unsignedVPTokenResults
    }

    private func createFormatToCredentialInputDescriptorMapping(
        matchingCredentials: [String: [FormatType: [AnyCodable]]]
    ) {
        var formatToCredentialInputDescriptorMapping: [FormatType: [CredentialInputDescriptorMapping]] = [:]

        for (inputDescriptorId, formatCredentialMap) in matchingCredentials {
            for (format, credentialsArray) in formatCredentialMap {
                for credential in credentialsArray {
                    let mapping = CredentialInputDescriptorMapping(
                        format: format,
                        credential: credential,
                        inputDescriptorId: inputDescriptorId
                    )
                    formatToCredentialInputDescriptorMapping[format, default: []].append(mapping)
                }
            }
        }
        self.formatToCredentialInputDescriptorMapping = formatToCredentialInputDescriptorMapping
    }

    private func toVerifierResponse(_ networkResponse: NetworkResponse) -> VerifierResponse {
        let redirectUriKey = "redirect_uri"

        var redirectUri: String?
        var additionalParams: String? = networkResponse.body

        if let data = networkResponse.body.data(using: .utf8),
           var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            redirectUri = json[redirectUriKey] as? String

            json.removeValue(forKey: redirectUriKey)
            if let cleanedData = try? JSONSerialization.data(withJSONObject: json, options: []),
               let cleanedString = String(data: cleanedData, encoding: .utf8) {
                additionalParams = cleanedString
            }
        }

        return VerifierResponse(
            statusCode: networkResponse.statusCode,
            responseBody: networkResponse.body,
            redirectUri: redirectUri,
            additionalParams: additionalParams,
            headers: networkResponse.headers
        )
    }

    private enum SpecVersionHandler {
        case draft23, specV1

        static func from(_ authorizationRequest: AuthorizationRequest) -> SpecVersionHandler {
            return authorizationRequest is AuthorizationPresentationExchangeRequest ? .draft23 : .specV1
        }
        
        func createUnsignedVPToken(credentialsMap: [String: [FormatType: [AnyCodable]]],
                                   authorizationRequest: AuthorizationRequest,
                                   holderId: String?,
                                   signatureSuite: String?,
                                   walletNonce: String,
                                   handler: AuthorizationResponseHandler) async throws -> [UnsignedVPTokenV2] {
            _ = try await handler.createUnsignedVPToken(credentialsMap: credentialsMap, authorizationRequest: authorizationRequest, walletNonce: walletNonce, holderId: holderId, signatureSuite: signatureSuite)
            
            return try await flattenUnsignedVPTokens(
                unsignedVPTokenResults: handler.unsignedVPTokenResults,
                formatMappings: handler.formatToCredentialInputDescriptorMapping,
                holderId: holderId,
                signatureSuite: signatureSuite
            )
        }

        func createVPTokenResponse(
            authorizationRequest: AuthorizationRequest,
            vpTokenSigningResults: [FormatType: VPTokenSigningResult],
            unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)],
            formatToCredentialInputDescriptorMapping: [FormatType: [CredentialInputDescriptorMapping]],
            handler: AuthorizationResponseHandler
        ) throws -> AuthorizationResponse {
            switch self {
            case .draft23:
                let (vpToken, presentationSubmission) = try handler.createVPTokenAndPresentationSubmission(
                    vpTokenSigningResults: vpTokenSigningResults,
                    authorizationRequest: authorizationRequest,
                    unsignedVPTokenResults: unsignedVPTokenResults,
                    formatToCredentialInputDescriptorMapping: formatToCredentialInputDescriptorMapping
                )
                return .presentationExchange(
                    vpToken: vpToken,
                    presentationSubmission: presentationSubmission,
                    state: authorizationRequest.state
                )
            case .specV1:
                return .dcql(vpToken: [:], state: authorizationRequest.state)
            }
        }

        func getPresentationDefinitionId(_ authorizationRequest: AuthorizationRequest) -> String {
            switch self {
            case .draft23:
                return (authorizationRequest as? AuthorizationPresentationExchangeRequest)?.presentationDefinition.id ?? ""
            case .specV1:
                return ""
            }
        }
    }
}
