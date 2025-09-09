
import Foundation

public class AuthorizationResponseHandler {
    private let networkManager: NetworkManaging
    private var unsignedVPTokens: [FormatType: [String:Any]] = [:]
    private var path: [FormatType: (index: Int, nestedIndex: Int)] = [:]
    private var credentialsMap: [String: [FormatType: Array<Any>]]?
    private var walletNonce: String = ""

    public static let className = String(describing: AuthorizationResponseHandler.self)

    public init(networkManager: NetworkManaging) {
        self.networkManager = networkManager
    }
    
    func constructUnsignedVPToken(credentialsMap: [String: [FormatType: [AnyCodable]]],
                               authorizationRequest: AuthorizationRequest,
                               responseUri: String,
                               holderId: String?,
                               signatureSuite: String?,
                               walletNonce: String
    ) async throws -> [FormatType: UnsignedVPToken] {
        let hasLdpVc = credentialsMap.values.contains { formatMap in
            formatMap.keys.contains(.ldp_vc)
        }
        if(hasLdpVc){
            // In case of ldp_vc, the Verifiable presentation created will have the info of holder and signature suite
            if (isNullOrEmpty(holderId)) {
                throw InvalidData(
                    message: "Holder ID cannot be null or empty for LDP VC format",
                    className: AuthorizationResponseHandler.className
                )
            }
            if(isNullOrEmpty(signatureSuite)){
                throw InvalidData(
                    message: "Signature Suite cannot be null or empty for LDP VC format",
                    className: AuthorizationResponseHandler.className
                )
            }
        }
        
        return try await createUnsignedVPToken(credentialsMap: credentialsMap, authorizationRequest: authorizationRequest, responseUri: responseUri, walletNonce: walletNonce, holderId: holderId, signatureSuite: signatureSuite)
        
    }

    private func createUnsignedVPToken(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
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

        self.credentialsMap = credentialsMap
        self.walletNonce = walletNonce

        unsignedVPTokens = try await createUnsignedVPTokens(
            credentialsMap: credentialsMap,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite
        )

        let unsignedVPTokensExtracted: [FormatType: UnsignedVPToken] = try unsignedVPTokens.mapValues { innerMap in
            guard let token = innerMap["unsignedVPToken"] as? UnsignedVPToken else {
                throw InvalidData(
                    message: "Missing or invalid 'unsignedVPToken' in VP token map",
                    className: AuthorizationResponseHandler.className
                )
            }
            return token
        }

        return unsignedVPTokensExtracted
    }


    public func shareVP(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [FormatType: VPTokenSigningResult],
        responseUri: String
    ) async throws -> String {
        let authorizationResponse = try createAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults
        )

        return try await sendAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            authorizationResponse: authorizationResponse,
            responseUri: responseUri
        )
    }

    private func createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: [FormatType: VPTokenSigningResult]
    ) throws -> AuthorizationResponse {
        switch authorizationRequest.responseType {
        case ResponseType.vp_token.rawValue:
            var credentialFormatIndex: [FormatType: Int] = [:]
            let vpToken = try createVPToken(
                vpTokenSigningResults: vpTokenSigningResults,
                authorizationRequest: authorizationRequest,
                credentialFormatIndex: &credentialFormatIndex
            )
            let presentationSubmission = createPresentationSubmission(
                credentialFormatIndex: &credentialFormatIndex, authorizationRequest: authorizationRequest
            )
            return AuthorizationResponse(
                vpToken: vpToken,
                presentationSubmission: presentationSubmission,
                state: authorizationRequest.state
            )
        default:
            throw InvalidData(
                message: "response type - \(authorizationRequest.responseType) is not supported",
                className: AuthorizationResponseHandler.className
            )
        }
    }

    private func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        responseUri: String
    ) async throws -> String {
        return try await ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode)
            .sendAuthorizationResponse(
                authorizationRequest: authorizationRequest,
                authorizationResponse: authorizationResponse,
                url: responseUri,
                networkManager: networkManager,
                producerInfo:walletNonce,
                recepientInfo: authorizationRequest.nonce
            )
    }

    private func createVPToken(
        vpTokenSigningResults: [FormatType: VPTokenSigningResult],
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: inout [FormatType: Int]
    ) throws -> VPTokenType {
        var vpTokens: [VPToken] = []

        var count = 0
        for (credentialFormat, vpTokenSigningResult) in vpTokenSigningResults.sorted(by: { $0.key.rawValue < $1.key.rawValue }) {
            var token : any VPToken
            if(credentialFormat == .vc_sd_jwt || credentialFormat == .dc_sd_jwt){
                guard let sdJwtVPTokenSigningResult = (vpTokenSigningResult as? SdJwtVpTokenSigningResult)?.uuidToKbJWTSignature else {
                    throw InvalidData(
                        message: "Invalid VPTokenSigningResult for SD-JWT format",
                        className: AuthorizationResponseHandler.className
                    )
                }
                for (uuid, _
                ) in sdJwtVPTokenSigningResult {
                    token = try VPTokenFactory(
                        vpTokenSigningResult: vpTokenSigningResult,
                        vpTokenSigningPayload: unsignedVPTokens[credentialFormat]?["vpTokenSigningPayload"] ?? {
                            throw InvalidData(
                                message: "unable to find the related credential format - \(credentialFormat) in the unsignedVPTokens map",
                                className: AuthorizationResponseHandler.className
                            )
                        }(),
                        unsignedVPTokens: unsignedVPTokens[credentialFormat]?["unsignedVPTokens"] ?? {
                            throw InvalidData(
                                message: "unable to find the related credential format - \(credentialFormat) in the unsignedVPTokens map",
                                className: AuthorizationResponseHandler.className
                            )
                        }(),
                        nonce: authorizationRequest.nonce,
                        uuid: uuid
                    ).getVPTokenBuilder(credentialFormat: credentialFormat).build()
                    vpTokens.append(token)
                    credentialFormatIndex[credentialFormat] = count
                    count += 1
                }
            } else {
                token = try VPTokenFactory(
                    vpTokenSigningResult: vpTokenSigningResult,
                    vpTokenSigningPayload: unsignedVPTokens[credentialFormat]?["vpTokenSigningPayload"] ?? {
                        throw InvalidData(
                            message: "unable to find the related credential format - \(credentialFormat) in the unsignedVPTokens map",
                            className: AuthorizationResponseHandler.className
                        )
                    }(),
                    nonce: authorizationRequest.nonce
                ).getVPTokenBuilder(credentialFormat: credentialFormat).build()
                vpTokens.append(token)
                credentialFormatIndex[credentialFormat] = count
                count += 1
            }
        }

        return vpTokens.count == 1
            ? .vpTokenElement(vpTokens[0])
            : .vpTokenArray(vpTokens)
    }

    private func createPresentationSubmission(
        credentialFormatIndex: inout [FormatType: Int],
        authorizationRequest: AuthorizationRequest
    ) -> PresentationSubmission {
        let descriptorMap = createInputDescriptor(
            credentialFormatIndex: &credentialFormatIndex
        )
        let presentationDefinitionId = authorizationRequest.presentationDefinition.id

        return PresentationSubmission(
            definitionId: presentationDefinitionId,
            descriptorMap: descriptorMap
        )
    }

    private func createInputDescriptor(
        credentialFormatIndex: inout [FormatType: Int]
    ) -> [DescriptorMap] {
        let multipleVPTokens = credentialFormatIndex.keys.count > 1
        var formatTypeToCredentialIndex: [FormatType: Int] = [:]

        return credentialsMap?.sorted(by: { $0.key < $1.key }).flatMap { inputDescriptorId, formatMap in
            formatMap.flatMap { credentialFormat, credentials in
                let vpTokenIndex = credentialFormatIndex[credentialFormat] ?? -1

                return credentials.map { _ in
                    let rootLevelPath = multipleVPTokens ? "$[\(vpTokenIndex)]" : "$"
                    let credentialIndex = (formatTypeToCredentialIndex[credentialFormat] ?? -1) + 1
                    let vpFormat: VPFormatType
                    let pathNested: PathNested?
                    
                    switch credentialFormat {
                    case .ldp_vc:
                        let relativePath = "$.\(LdpVPToken.internalPath)[\(credentialIndex)]"
                        vpFormat = .ldp_vp
                        pathNested = PathNested(
                            id: inputDescriptorId,
                            format: credentialFormat,
                            path: relativePath
                        )
                    case .mso_mdoc:
                        pathNested = nil
                        vpFormat = .mso_mdoc
                        
                    case .dc_sd_jwt:
                        pathNested = nil
                        vpFormat = .dc_sd_jwt
                        
                    case .vc_sd_jwt :
                        pathNested = nil
                        vpFormat = .vc_sd_jwt
                    }
                    
                    formatTypeToCredentialIndex[credentialFormat] = credentialIndex
                    
                    return DescriptorMap(
                        id: inputDescriptorId,
                        format: vpFormat,
                        path: rootLevelPath,
                        pathNested: pathNested
                    )
                }
            }
        } ?? []
    }

    private func createUnsignedVPTokens(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String?,
        signatureSuite: String?
    ) async throws -> [FormatType: [String: Any]] {
        let groupedVcs: [FormatType: [AnyCodable]] = credentialsMap
            .compactMap { $0.value }
            .reduce(into: [FormatType: [AnyCodable]]()) { result, entry in
                for (format, creds) in entry {
                    result[format, default: []].append(contentsOf: creds)
                }
            }

        var result: [FormatType: [String: Any]] = [:]

        for (format, credentialsArray) in groupedVcs {
            switch format {
            case .ldp_vc:
                //TODO: Add unit test for this
                guard let holderId = holderId else {
                    throw InvalidData(
                        message: "Holder ID cannot be null for LDP VC format",
                        className: AuthorizationResponseHandler.className
                    )
                }
                let token = UnsignedLdpVPTokenBuilder(
                    verifiableCredential: credentialsArray,
                    id: UUIDGenerator.generateUUID(),
                    holder: holderId,
                    challenge: authorizationRequest.nonce,
                    domain: authorizationRequest.clientId,
                    signatureSuite: signatureSuite!
                ).build()
                result[format] = token
            case .mso_mdoc:
                let mdocCreds = try credentialsArray
                    .map { anyCodable in
                        guard let str = anyCodable.value as? String else {
                            throw InvalidData(
                                message: "MDOC credential is not a String",
                                className: AuthorizationResponseHandler.className
                            )
                        }
                        return str
                    }
                let token = try UnsignedMdocVPTokenBuilder(
                    mdocCredentials: mdocCreds,
                    clientId: authorizationRequest.clientId,
                    responseUri: responseUri,
                    verifierNonce: authorizationRequest.nonce,
                    mdocGeneratedNonce: walletNonce
                ).build()
                result[format] = token
                
            case .dc_sd_jwt, .vc_sd_jwt:
                let sdJwtCreds = try credentialsArray
                    .map { anyCodable in
                        guard let str = anyCodable.value as? String else {
                            throw InvalidData(
                                message: "SD-JWT credential is not a String",
                                className: AuthorizationResponseHandler.className
                            )
                        }
                        return str
                    }
                let token = try await UnsignedSdJWTVPTokenBuilder(
                    clientId: authorizationRequest.clientId, authorizationRequestNonce: authorizationRequest.nonce, credentials: sdJwtCreds
                    ).build()
                result[format] = token
            }
        }

        return result
    }

    @available(*, deprecated, message: "This method supports constructing VP token for LDP VC without canonicalization of the data sent for signing. use constructUnsignedVPToken instead")
    func constructUnsignedVPTokenV1(
        verifiableCredentials: [String: [String]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        walletNonce: String
    ) async throws -> String {
        let transformedCredentials: [String: [FormatType: [AnyCodable]]] = verifiableCredentials.mapValues { credentials in
            let wrapped = credentials.map { AnyCodable($0) }
            return [.ldp_vc: wrapped]
        }

        let unsignedVPToken = try await createUnsignedVPToken(
            credentialsMap: transformedCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            walletNonce: walletNonce,
            holderId: "",
            signatureSuite: "Ed25519Signature2020"
        )

        var ldpToken = unsignedVPTokens[.ldp_vc]?["vpTokenSigningPayload"] as? LdpVPToken

        ldpToken?.proof = nil

        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            encoder.keyEncodingStrategy = .useDefaultKeys
            let encodedData = try encoder.encode(ldpToken)

            guard let jsonString = String(data: encodedData, encoding: .utf8) else {
                throw JsonEncodingFailed(
                    fieldPath: ["unsignedLdpVPToken"],
                    errorMessage: "Failed to convert encoded data to UTF-8 string",
                    className: "AuthorizationResponseHandler"
                )
            }

            return jsonString
        } catch {
            throw JsonEncodingFailed(
                fieldPath: ["unsignedLdpVPToken"],
                errorMessage: error.localizedDescription,
                className: "AuthorizationResponseHandler"
            )
        }
    }

    
    @available(*, deprecated, message: "Use shareVP instead")
    func shareVPV1(
        vpResponseMetadata: VPResponseMetadata,
        nonce: String,
        state: String?,
        responseUri: String,
        presentationDefinitionId: String
    ) async throws -> String {
        do {
            try vpResponseMetadata.validate()
            var pathIndex = 0

            // Flatten credentials
            let flattenedCredentials: [String: [Any]] = (credentialsMap?.mapValues { $0.values.first ?? [] })!

            // Build descriptor map
            var descriptorMap: [DescriptorMap] = []
            for (inputDescriptorId, vcs) in flattenedCredentials {
                for _ in vcs {
                    descriptorMap.append(
                        DescriptorMap(
                            id: inputDescriptorId,
                            format: VPFormatType.ldp_vp,
                            path: "$.verifiableCredential[\(pathIndex)]",
                            pathNested: nil
                        )
                    )
                    pathIndex += 1
                }
            }

            let presentationSubmission = PresentationSubmission(
                definitionId: presentationDefinitionId,
                descriptorMap: descriptorMap
            )

            guard let unsignedLdpVPTokenMap = unsignedVPTokens[.ldp_vc],
                  var unsignedLdpVPToken = unsignedVPTokens[FormatType.ldp_vc]!["vpTokenSigningPayload"] as? LdpVPToken else {
                throw NSError(domain: "Missing unsignedLdpVPToken", code: 0)
            }

            // Construct final VP Token
            unsignedLdpVPToken.proof?.verificationMethod = vpResponseMetadata.publicKey
            unsignedLdpVPToken.proof?.proofValue = vpResponseMetadata.jws

            print("AuthorizationResponseHandler VP Token: \(unsignedLdpVPToken)")

            return try await constructHttpRequestBody(
                vpToken: unsignedLdpVPToken,
                presentationSubmission: presentationSubmission,
                responseUri: responseUri,
                state: state
            )

        } catch {
            throw error
        }
    }
    
    @available(*, deprecated, message: "This is a private method used by shareVPV1 and should not be used directly.")
    private func constructHttpRequestBody(
        vpToken: VPToken,
        presentationSubmission: PresentationSubmission,
        responseUri: String,
        state: String?
    ) async throws -> String {
        let encodedVPToken: String
        let encodedPresentationSubmission: String

        do {
            let jsonData = try JSONEncoder().encode(vpToken)
            encodedVPToken = String(data: jsonData, encoding: .utf8) ?? ""
        } catch {
            throw JsonEncodingFailed(
                fieldPath: ["vp_token"],
                errorMessage: error.localizedDescription,
                className: "AuthorizationResponseHandler"
            )
        }

        do {
            let jsonData = try JSONEncoder().encode(presentationSubmission)
            encodedPresentationSubmission = String(data: jsonData, encoding: .utf8) ?? ""
        } catch {
            throw JsonEncodingFailed(
                fieldPath: ["presentation_submission"],
                errorMessage: error.localizedDescription,
                className: "AuthorizationResponseHandler"
            )
        }

        do {
            var bodyParams: [String: String] = [
                "vp_token": encodedVPToken,
                "presentation_submission": encodedPresentationSubmission,
            ]

            if let state = state {
                bodyParams["state"] = state
            }

            let response = try await networkManager.sendHTTPRequest(
                url: responseUri,
                method: .post,
                bodyParams: bodyParams,
                headers: ["content-type": "application/x-www-form-urlencoded"]
            )

            return response.responseBody
        } catch {
            throw error
        }
    }
}
