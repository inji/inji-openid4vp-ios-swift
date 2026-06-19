import Foundation

class SdJwtVPTokenBuilder : VPTokenBuilder {
    let authorizationRequest: AuthorizationRequest
    
    init(authorizationRequest: AuthorizationRequest) {
        self.authorizationRequest = authorizationRequest
    }
    
    private let className = String(describing: SdJwtVPTokenBuilder.self)
    
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        var vpIndex = rootIndex
        let uuidToUnsignedKBT = try extractUuidToUnsignedKBT(from: unsignedVPTokenResult)
        var vpTokens: [VPToken] = []
        var descriptorMaps: [DescriptorMap] = []
        var signingResultsIterator = vpTokenSigningResults.makeIterator()

        for mapping in credentialInputDescriptorMappings {
            let uuid = try extractUUID(from: mapping.identifier)
            let sdJwtCredential = try extractSDJwtString(from: mapping.credential, className: className)
            let unsignedKBJwt = uuidToUnsignedKBT[uuid]
            let finalVPToken = try buildFinalToken(
                uuid: uuid,
                sdJwtCredential: sdJwtCredential,
                unsignedKBJwt: unsignedKBJwt,
                signingResultsIterator: &signingResultsIterator
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

        try assertNoExtraSigningResults(&signingResultsIterator)
        return (vpTokens, descriptorMaps, vpIndex)
    }

    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        let uuidToUnsignedKBT = try extractUuidToUnsignedKBT(from: unsignedVPTokenResult)
        var vpTokenResult: [String: [VPToken]] = [:]
        var signingResultsIterator = vpTokenSigningResults.makeIterator()

        for mapping in credentialToCredentialQueryIdMappings {
            let uuid = try extractUUID(from: mapping.identifier)
            let credentialQuery = try matchingDCQLCredentialQuery(authorizationRequest, for: mapping.credentialQueryId, className: className)
            let sdJwtCredential = try extractSDJwtString(from: mapping.credential, className: className)
            let unsignedKBJwt = uuidToUnsignedKBT[uuid]

            let finalVPToken: String
            if credentialQuery.requireCryptographicHolderBinding {
                if unsignedKBJwt == nil {
                    throw InvalidData(message: "Missing Key Binding JWT for uuid: \(uuid)", className: className)
                }
                finalVPToken = try buildFinalToken(
                    uuid: uuid,
                    sdJwtCredential: sdJwtCredential,
                    unsignedKBJwt: unsignedKBJwt,
                    signingResultsIterator: &signingResultsIterator
                )
            } else {
                guard unsignedKBJwt == nil else {
                    throw InvalidData(message: "Unexpected key binding jwt for uuid: \(uuid)", className: className)
                }
                finalVPToken = sdJwtCredential
            }

            vpTokenResult[mapping.credentialQueryId, default: []].append(SdJwtVPToken(value: finalVPToken))
        }

        try assertNoExtraSigningResults(&signingResultsIterator)
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

    private func extractUUID(from identifier: String?) throws -> String {
        guard let uuid = identifier else {
            throw InvalidData(message: "identifier is null in CredentialInputDescriptorMapping for SD-JWT", className: className)
        }
        return uuid
    }

    private func buildFinalToken(
        uuid: String,
        sdJwtCredential: String,
        unsignedKBJwt: String?,
        signingResultsIterator: inout IndexingIterator<[VPTokenSigningResult]>
    ) throws -> String {
        guard let unsignedKBJwt else {
            return sdJwtCredential
        }
        guard let vpTokenSigningResult = signingResultsIterator.next() else {
            throw InvalidData(message: "Missing signing result for \(uuid)", className: className)
        }
        let signature = vpTokenSigningResult.signedData.toBase64UrlEncoded()
        guard !signature.isEmpty else {
            throw MissingInput(fieldPath: uuid, message: "Missing Key Binding JWT signature for uuid: \(uuid)", className: className)
        }
        return "\(sdJwtCredential)\(unsignedKBJwt).\(signature)"
    }

    private func assertNoExtraSigningResults(_ iterator: inout IndexingIterator<[VPTokenSigningResult]>) throws {
        if iterator.next() != nil {
            throw InvalidData(message: "Extra signing results provided for SD-JWT", className: className)
        }
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
