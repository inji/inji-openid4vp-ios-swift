import Foundation

class SdJwtVPTokenBuilder : VPTokenBuilder {
    let authorizationRequest: AuthorizationRequest
    
    init(authorizationRequest: AuthorizationRequest) {
        self.authorizationRequest = authorizationRequest
    }
    
    private let className = String(describing: SdJwtVPTokenBuilder.self)
    
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        var vpIndex = rootIndex
        let uuidToUnsignedKBT = try extractUuidToUnsignedKBT(from: unsignedVPTokenResult)
        var vpTokens: [VPToken] = []
        var descriptorMaps: [DescriptorMap] = []

        for mapping in credentialInputDescriptorMappings {
            let identifier = try extractIdentifier(from: mapping.identifier)
            let sdJwtCredential = try extractSDJwtString(from: mapping.credential, className: className)
            let unsignedKBJwt = uuidToUnsignedKBT[identifier]
            let finalVPToken = try buildFinalToken(
                identifier: identifier,
                sdJwtCredential: sdJwtCredential,
                unsignedKBJwt: unsignedKBJwt,
                vpTokenSigningResults: vpTokenSigningResults
            )
            vpTokens.append(SdJwtVPToken(value: finalVPToken))
            descriptorMaps.append(
                DescriptorMap(
                    id: mapping.inputDescriptorId,
                    format: vpFormat(mapping.format),
                    path: createDescriptorMapPath(vpIndex),
                    pathNested: createNestedPath(id: mapping.inputDescriptorId, nestedPath: mapping.nestedPath, format: mapping.format)
                )
            )
            vpIndex += 1
        }

        return (vpTokens, descriptorMaps, vpIndex)
    }

    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: VPTokenSigningPayload, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        let uuidToUnsignedKBT = try extractUuidToUnsignedKBT(from: unsignedVPTokenResult)
        var vpTokenResult: [String: [VPToken]] = [:]

        for mapping in credentialToCredentialQueryIdMappings {
            let identifier = try extractIdentifier(from: mapping.identifier)
            let credentialQuery = try matchingDCQLCredentialQuery(authorizationRequest, for: mapping.credentialQueryId, className: className)
            let sdJwtCredential = try extractSDJwtString(from: mapping.credential, className: className)
            let unsignedKBJwt = uuidToUnsignedKBT[identifier]

            let finalVPToken: String
            if credentialQuery.requireCryptographicHolderBinding {
                if unsignedKBJwt == nil {
                    throw InvalidData(message: "Missing Key Binding JWT for uuid: \(identifier)", className: className)
                }
                finalVPToken = try buildFinalToken(
                    identifier: identifier,
                    sdJwtCredential: sdJwtCredential,
                    unsignedKBJwt: unsignedKBJwt,
                    vpTokenSigningResults: vpTokenSigningResults
                )
            } else {
                guard unsignedKBJwt == nil else {
                    throw InvalidData(message: "Unexpected key binding jwt for uuid: \(identifier)", className: className)
                }
                finalVPToken = sdJwtCredential
            }

            vpTokenResult[mapping.credentialQueryId, default: []].append(SdJwtVPToken(value: finalVPToken))
        }

        return vpTokenResult
    }

    private func extractUuidToUnsignedKBT(
        from unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken])
    ) throws -> [String: String] {
        guard let uuidToUnsignedKBT = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
            throw InvalidData(message: "Missing uuidToUnsignedKBT in payload", className: className)
        }
        return uuidToUnsignedKBT
    }

    private func extractIdentifier(from identifier: String?) throws -> String {
        guard let uuid = identifier else {
            throw InvalidData(message: "identifier is null in CredentialInputDescriptorMapping for SD-JWT", className: className)
        }
        return uuid
    }

    private func buildFinalToken(
        identifier: String,
        sdJwtCredential: String,
        unsignedKBJwt: String?,
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> String {
        guard let unsignedKBJwt else {
            return sdJwtCredential
        }
        let vpTokenSigningResult = try getVPTokenSigningResult(vpTokenSigningResults: vpTokenSigningResults, identifier: identifier, className: className)
        let signature = vpTokenSigningResult.signedData.toBase64UrlEncoded()
        return "\(sdJwtCredential)\(unsignedKBJwt).\(signature)"
    }
    
    private func vpFormat(_ value: FormatType) -> VPFormatType {
         switch value {
        case .dc_sd_jwt:
             return .dc_sd_jwt
        default:
             return .vc_sd_jwt
        }
    }
}
