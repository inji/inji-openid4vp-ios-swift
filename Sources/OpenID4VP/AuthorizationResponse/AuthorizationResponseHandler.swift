import Foundation
public class AuthorizationResponseHandler {
    private let networkManager: NetworkManaging
    private var unsignedVPTokens: [FormatType: UnsignedVPToken] = [:]
    private var path: [FormatType: (index: Int, nestedIndex: Int)] = [:]
    private var credentialsMap: [String: [FormatType: Array<Any>]]?
    private let walletNonce: String
    
    public static let className = String(describing: AuthorizationResponseHandler.self)
    
    public init(networkManager: NetworkManaging) {
        self.networkManager = networkManager
        //Nonce of entropy 16 bytes
        self.walletNonce =  (createNonce())
    }
    
    func constructUnsignedVPToken(
        credentialsMap: [String: [FormatType: Array<Any>]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String
    ) throws -> [FormatType: UnsignedVPToken] {
        if (credentialsMap.isEmpty) {
            throw Logger.handleException(
                exceptionType : "InvalidData",
                message : "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.", className : AuthorizationResponseHandler.className
            )
        }
        self.credentialsMap = credentialsMap
        self.unsignedVPTokens = try createUnsignedVPTokens(credentialsMap: credentialsMap, authorizationRequest: authorizationRequest, responseUri: responseUri)
        return self.unsignedVPTokens
    }
    
    func shareVP(
        authorizationRequest: AuthorizationRequest,
        vpResponsesMetadata: [FormatType: VPResponseMetadata],
        responseUri: String
    ) async throws -> String {
        let authorizationResponse: AuthorizationResponse = try createAuthorizationResponse(
            authorizationRequest : authorizationRequest,
            vpResponsesMetadata : vpResponsesMetadata
        )
        
        return try await sendAuthorizationResponse(
            authorizationRequest: authorizationRequest,
            authorizationResponse : authorizationResponse,
            responseUri : responseUri
        )
    }
    
    //Create authorization response based on response_type
    private func createAuthorizationResponse(authorizationRequest: AuthorizationRequest, vpResponsesMetadata : [FormatType: VPResponseMetadata]) throws -> AuthorizationResponse {
        switch authorizationRequest.responseType {
        case ResponseType.vp_token.rawValue:
            var credentialFormatIndex: [FormatType: Int] = [:]
            let vpToken = try createVPToken(
                vpResponsesMetadata: vpResponsesMetadata,
                authorizationRequest: authorizationRequest,
                credentialFormatIndex: &credentialFormatIndex
            )
            let presentationSubmission: PresentationSubmission = createPresentationSubmission(
                authorizationRequest: authorizationRequest,
                credentialFormatIndex: &credentialFormatIndex
            )
            
            return AuthorizationResponse(vpToken: vpToken, presentation_submission: presentationSubmission, state: authorizationRequest.state)
        default:
            throw Logger.handleException(exceptionType: "InvalidData", message: "response type - \(authorizationRequest.responseType) is not supported", className: AuthorizationResponseHandler.className)
        }
    }
    
    //Send authorization response based on response_mode
    private func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest ,authorizationResponse: AuthorizationResponse, responseUri: String) async throws -> String {
        return try await ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode)
            .sendAuthorizationResponse(authorizationRequest: authorizationRequest, authorizationResponse: authorizationResponse, url: responseUri, networkManager: networkManager)
    }
    
    private func createUnsignedVPTokens(credentialsMap: [String: [FormatType: [Any]]], authorizationRequest: AuthorizationRequest, responseUri : String) throws -> [FormatType: UnsignedVPToken] {
        let groupedVcs: [FormatType: [Any]] = credentialsMap
            .sorted(by: { $0.key < $1.key })
            .compactMap { $0.value }
            .reduce(into: [FormatType: [String]]()) { result, entry in
                for (key, value) in entry {
                    result[key, default: []].append(contentsOf: value)
                }
            }
        
        // group all formats together, call specific creator and pass the grouped credentials
        return try groupedVcs.reduce(into: [FormatType: UnsignedVPToken]()) { result, entry in
            let (format, credentials) = entry
            switch format {
            case .ldp_vc:
                guard let stringCredentials = credentials as? [String] else {
                    throw Logger.handleException(
                        exceptionType : "InvalidData",
                        message : "\(format) credentials are not passed in string format", className : AuthorizationResponseHandler.className
                    )
                }
                result[format] = try UnsignedLdpVPTokenBuilder(verifiableCredential: stringCredentials, id: UUIDGenerator.generateUUID(), holder: "").build()
            case .mso_mdoc:
                guard let stringCredentials = credentials as? [String] else {
                    throw Logger.handleException(
                        exceptionType : "InvalidData",
                        message : "\(format) credentials are not passed in string format", className : AuthorizationResponseHandler.className
                    )
                }
                result[format] = try UnsignedMdocVPTokenBuilder(mdocCredentials: stringCredentials, clientId: authorizationRequest.clientId, responseUri: responseUri, verifierNonce: authorizationRequest.nonce, mdocGeneratedNonce: walletNonce).build()
            }
        }
    }
    
    private func createVPToken(
        vpResponsesMetadata: [FormatType: VPResponseMetadata],
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: inout [FormatType: Int]
    ) throws -> VPTokenType {
        var vpTokens: [VPToken] = []
                
        // create an map of credential format to credentials from credentialsMap
        let groupedVcs: [FormatType: [Any]] = credentialsMap?
            .compactMap { $0.value }
            .reduce(into: [FormatType: [Any]]()) { result, entry in
                for (key, value) in entry {
                    result[key, default: []].append(contentsOf: value)
                }
            } ?? [:]
        
        var count = 0
        for (credentialFormat, vpResponseMetadata) in vpResponsesMetadata {
            let vpToken = try VPTokenFactory(
                vpResponseMetadata: vpResponseMetadata,
                unsignedVPToken: unsignedVPTokens[credentialFormat] ?? {
                    throw Logger.handleException(exceptionType: "InvalidData", message: "unable to find the related credential format - \(credentialFormat) in the unsignedVPTokens map", className: AuthorizationResponseHandler.className)
                }(),
                nonce: authorizationRequest.nonce,
                groupedVcs: groupedVcs
            ).getVPTokenBuilder(credentialFormat: credentialFormat).build()
            
            vpTokens.append(vpToken)
            credentialFormatIndex[credentialFormat] = count
            count += 1
        }
        
        let vpToken: VPTokenType = vpTokens.count == 1
        ? VPTokenType.vpTokenElement(vpTokens[0])
        : VPTokenType.vpTokenArray(vpTokens)
        
        return vpToken
    }
    
    private func createPresentationSubmission(
        authorizationRequest: AuthorizationRequest,
        credentialFormatIndex: inout [FormatType: Int]
    ) -> PresentationSubmission {
        let descriptorMap = createInputDescriptor(credentialsMap: credentialsMap!, credentialFormatIndex: &credentialFormatIndex)
        let presentationDefinitionId = (authorizationRequest.presentationDefinition ).id
        
        return PresentationSubmission(
            definition_id: presentationDefinitionId,
            descriptor_map: descriptorMap
        )
    }
    
    
    
    private func createInputDescriptor(
        credentialsMap: [String: [FormatType: [Any]]],
        credentialFormatIndex: inout [FormatType: Int]
    ) -> [DescriptorMap] {
        // In case of only single VP, presentation_submission -> path = $, path_nest = $.<credentialPathIdentifier - internalPath>[n]
        // and in case of multiple VPs, presentation_submission -> path = $[i], path_nest = $[i].<credentialPathIdentifier - internalPath>[n]
        let multipleVpTokens = credentialFormatIndex.keys.count > 1
        var formatTypeToCredentialIndex: [FormatType: Int] = [:]
        
        let descriptorMappings = credentialsMap.sorted(by: { $0.key < $1.key }).flatMap { (inputDescriptorId, formatMap) in
            formatMap.flatMap { (credentialFormat, credentials) in
                let vpTokenIndex = credentialFormatIndex[credentialFormat] ?? -1
                
                return credentials.map { credential in
                    let rootLevelPath = multipleVpTokens ? "$[\(vpTokenIndex)]" : "$"
                    let credentialIndex = (formatTypeToCredentialIndex[credentialFormat] ?? -1) + 1
                    let vpFormat: VPFormatType
                    let pathNested: PathNested?
                    switch credentialFormat {
                    case .ldp_vc:
                        let relativePath = "$.\(LdpVpToken.internalPath)[\(credentialIndex)]"
                        vpFormat = .ldp_vp
                        pathNested = PathNested(
                            id: inputDescriptorId,
                            format: credentialFormat,
                            path: relativePath
                        )
                    case .mso_mdoc:
                        // In case of mso_mdoc, path is $[i]
                        pathNested = nil
                        vpFormat = .mso_mdoc
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
        }
        return descriptorMappings
    }
    
    
}
