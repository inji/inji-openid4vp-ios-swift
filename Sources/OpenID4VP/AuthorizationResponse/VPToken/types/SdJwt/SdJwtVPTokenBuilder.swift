import Foundation

class SdJwtVPTokenBuilder : VPTokenBuilder {
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

            guard let sdJwtCredential = mapping.credential.value as? String else {
                throw InvalidData(message: "SD-JWT credential is not a String", className: className)
            }

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
    
    private func vpFormat(_ value: FormatType) -> VPFormatType {
         switch value {
        case .dc_sd_jwt:
             return .dc_sd_jwt
        default:
             return .vc_sd_jwt
        }
    }
}
