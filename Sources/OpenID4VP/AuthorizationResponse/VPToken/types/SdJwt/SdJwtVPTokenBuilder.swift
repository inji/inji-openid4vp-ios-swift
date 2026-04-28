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
        guard let uuidToUnsignedKBT = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
             throw InvalidData(message: "Missing uuidToUnsignedKBT in payload", className: className)
        }
        
        var vpTokens: [VPToken] = []
        var descriptorMaps: [DescriptorMap] = []
        var signingResultsIterator = vpTokenSigningResults.makeIterator()

        for mapping in credentialInputDescriptorMappings {
            guard let uuid = mapping.identifier else {
                throw InvalidData(message: "identifier is null in CredentialInputDescriptorMapping for SD-JWT", className: className)
            }

            let sdJwtCredential = try extractSDJwtString(from: mapping.credential, className: className)

            let unsignedKBJwt = uuidToUnsignedKBT[uuid]
            let finalVPToken: String
            
            if unsignedKBJwt == nil {
                finalVPToken = sdJwtCredential
            } else {
                guard let vpTokenSigningResult = signingResultsIterator.next() else {
                    throw InvalidData(message: "Missing signing result for \(uuid)", className: className)
                }

                let signature = vpTokenSigningResult.signedData
                guard !signature.isEmpty, let unsignedKBJwt else {
                    throw MissingInput(fieldPath: uuid, message: "Missing Key Binding JWT signature for uuid: \(uuid)", className: className)
                }
                finalVPToken = "\(sdJwtCredential)\(unsignedKBJwt).\(signature)"
            }
            
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

        if signingResultsIterator.next() != nil {
            throw InvalidData(message: "Extra signing results provided for SD-JWT", className: className)
        }

        return (vpTokens, descriptorMaps, vpIndex)
    }
    
    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        guard let uuidToUnsignedKBT = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
             throw InvalidData(message: "Missing uuidToUnsignedKBT in payload", className: className)
        }
        
        var vpTokenResult: [String: [VPToken]] = [:]
        var signingResultsIterator = vpTokenSigningResults.makeIterator()

        for credentialToCredentialQueryIdMapping in credentialToCredentialQueryIdMappings {
            guard let uuid = credentialToCredentialQueryIdMapping.identifier else {
                throw InvalidData(message: "identifier is null in CredentialInputDescriptorMapping for SD-JWT", className: className)
            }
            
            let credentialQuery = try matchingDCQLCredentialQuery(authorizationRequest, for: credentialToCredentialQueryIdMapping.credentialQueryId, className: className)
            

            let sdJwtCredential = try extractSDJwtString(from: credentialToCredentialQueryIdMapping.credential, className: className)

            let unsignedKBJwt = uuidToUnsignedKBT[uuid]
            let finalVPToken: String
            
            if(credentialQuery.requireCryptographicHolderBinding) {
                if unsignedKBJwt == nil {
                    throw InvalidData(message: "Missing Key Binding JWT for uuid: \(uuid)", className: className)
                }
                guard let vpTokenSigningResult = signingResultsIterator.next() else {
                    throw InvalidData(message: "Missing signing result for \(uuid)", className: className)
                }

                let signature = vpTokenSigningResult.signedData
                guard !signature.isEmpty, let unsignedKBJwt else {
                    throw MissingInput(fieldPath: uuid, message: "Missing Key Binding JWT signature for uuid: \(uuid)", className: className)
                }
                finalVPToken = "\(sdJwtCredential)\(unsignedKBJwt).\(signature)"
            } else {
                if unsignedKBJwt != nil {
                    throw InvalidData(message: "Unexpected key binding jwt for uuid: \(uuid)", className: className)
                }
                finalVPToken = sdJwtCredential
            }
            
            vpTokenResult[credentialToCredentialQueryIdMapping.credentialQueryId, default: []]
                .append(SdJwtVPToken(value: finalVPToken))
            
        }

        if signingResultsIterator.next() != nil {
            throw InvalidData(message: "Extra signing results provided for SD-JWT", className: className)
        }

        return vpTokenResult
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
