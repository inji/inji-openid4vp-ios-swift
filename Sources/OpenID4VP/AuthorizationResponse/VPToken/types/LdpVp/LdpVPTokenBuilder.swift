import Foundation

class LdpVPTokenBuilder: VPTokenBuilder {
    private let className = "LdpVPTokenBuilder"
    
    let authorizationRequest: AuthorizationRequest
    
    init(authorizationRequest: AuthorizationRequest) {
        self.authorizationRequest = authorizationRequest
    }

    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        guard let vpTokenSigningResult = vpTokenSigningResults.first else {
            throw InvalidData(message: "vpTokenSigningResult is missing", className: className)
        }
        guard let unsignedLdpVPToken = unsignedVPTokenResult.vpTokenSigningPayload as? LdpVPToken else {
            throw InvalidData(message: "payload is not LdpVPToken", className: className)
        }
        
        var proof = unsignedLdpVPToken.proof
        let signatureSuite = proof?.type ?? ""

        switch signatureSuite {
        case SignatureAlgorithm.rsaSignature2018.rawValue,
            SignatureAlgorithm.ed25519Signature2018.rawValue:
            try validateField(
                field: vpTokenSigningResult.signedData,
                fieldPath: ["VPTokenSigningResult", "signedData"],
                className: className
            )
            guard let unsignedVPToken = unsignedVPTokenResult.unsignedVPTokens.first else {
                throw InvalidData(message: "Missing data to sign", className: className)
            }
            let preHash = unsignedVPToken.dataToSign
            let header = preHash.split(separator: ".").first ?? ""
            proof?.jws = header + ".." + vpTokenSigningResult.signedData
        
        case SignatureAlgorithm.jsonWebSignature2020.rawValue:
            try validateField(
                field: vpTokenSigningResult.signedData,
                fieldPath: ["VPTokenSigningResult", "signedData"],
                className: className
            )
            guard let unsignedVPToken = unsignedVPTokenResult.unsignedVPTokens.first else {
                throw InvalidData(message: "Missing data to sign", className: className)
            }
            let preHash = unsignedVPToken.dataToSign
            proof?.jws = preHash + "." + vpTokenSigningResult.signedData

        case SignatureAlgorithm.ed25519Signature2020.rawValue:
            try validateField(
                field: vpTokenSigningResult.signedData,
                fieldPath: ["VPTokenSigningResult", "signedData"],
                className: className
            )
            proof?.proofValue = vpTokenSigningResult.signedData

        default:
            throw UnsupportedSignatureAlgorithm(
                message: "Unsupported algorithm: \(signatureSuite)",
                className: className
            )
        }

        let ldpVPToken = LdpVPToken(
            context: unsignedLdpVPToken.context,
            type: unsignedLdpVPToken.type,
            verifiableCredential: unsignedLdpVPToken.verifiableCredential,
            id: unsignedLdpVPToken.id,
            holder: unsignedLdpVPToken.holder,
            proof: proof!
        )
        let descriptorMaps = credentialInputDescriptorMappings.map { mapping in
            DescriptorMap(
                id: mapping.inputDescriptorId,
                format: .ldp_vp,
                path: createDescriptorMapPath(rootIndex),
                pathNested: createNestedPath(
                    id: mapping.inputDescriptorId,
                    nestedPath: mapping.nestedPath,
                    format: .ldp_vc
                )
            )
        }
        return ([ldpVPToken], descriptorMaps, rootIndex + 1)
    }
    
    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        var vpTokenSigningResultsIterator = vpTokenSigningResults.makeIterator()
        var vpTokenResult : [String: [VPToken]] = [:]
        var unsignedVpTokenIterator = unsignedVPTokenResult.unsignedVPTokens.makeIterator()
        guard let unsignedVpTokens = unsignedVPTokenResult.vpTokenSigningPayload as? [String: LdpVPToken] else {
             throw InvalidData(message: "Missing uuidToUnsignedKBT in payload", className: className)
        }
        for credentialToCredentialQueryIdMapping in credentialToCredentialQueryIdMappings {
            let credentialQuery = try matchingDCQLCredentialQuery(authorizationRequest, for: credentialToCredentialQueryIdMapping.credentialQueryId, className: className)
            
            guard let unsignedLdpVPToken = unsignedVpTokens[credentialToCredentialQueryIdMapping.identifier ?? ""] else {
                throw InvalidData(message: "Missing unsigned VP token for identifier \(credentialToCredentialQueryIdMapping.identifier ?? "")", className: className)
            }
            var proof = unsignedLdpVPToken.proof
            
            if(credentialQuery.requireCryptographicHolderBinding) {
                guard let vpTokenSigningResult = vpTokenSigningResultsIterator.next() else {
                    throw InvalidData(message: "Missing signing result for identifier \(credentialToCredentialQueryIdMapping.identifier ?? "")", className: className)
                }
                
                try validateField(
                    field: vpTokenSigningResult.signedData,
                    fieldPath: ["VPTokenSigningResult", "signedData"],
                    className: className
                )
                guard let unsignedVPToken = unsignedVpTokenIterator.next() else {
                    throw InvalidData(message: "Missing data to sign", className: className)
                }
                let preHash = unsignedVPToken.dataToSign
                let header = preHash.split(separator: ".").first ?? ""
                proof?.jws = header + ".." + vpTokenSigningResult.signedData
            }
            
            let ldpVPToken = LdpVPToken(
                context: unsignedLdpVPToken.context,
                type: unsignedLdpVPToken.type,
                verifiableCredential: unsignedLdpVPToken.verifiableCredential,
                id: unsignedLdpVPToken.id,
                holder: unsignedLdpVPToken.holder,
                proof: proof
            )
            
            vpTokenResult[credentialQuery.id, default: []].append(ldpVPToken)
        }
        
        
        return vpTokenResult
    }
}
