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
        case SignatureAlgorithm.jsonWebSignature2020.rawValue,
            SignatureAlgorithm.rsaSignature2018.rawValue,
            SignatureAlgorithm.ed25519Signature2018.rawValue:
            try validateField(
                field: vpTokenSigningResult.signedData,
                fieldPath: ["VPTokenSigningResult", "signedData"],
                className: className
            )
            proof?.jws = vpTokenSigningResult.signedData

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
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> [String: [VPToken]] {
        var index = 0;
        for credentialToCredentialQueryIdMapping in credentialToCredentialQueryIdMappings {
            
        }
        
        
        return [:]
    }
    
//    func build(
//        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
//        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
//        vpTokenSigningResults: [VPTokenSigningResult],
//        rootIndex: Int
//    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
//        guard let vpTokenSigningResult = vpTokenSigningResults.first else {
//            throw InvalidData(message: "vpTokenSigningResult is missing", className: className)
//        }
//        guard let unsignedLdpVPToken = unsignedVPTokenResult.vpTokenSigningPayload as? LdpVPToken else {
//            throw InvalidData(message: "payload is not LdpVPToken", className: className)
//        }
//        
//        var proof = unsignedLdpVPToken.proof
//        let signatureSuite = proof?.type ?? ""
//
//        switch signatureSuite {
//        case SignatureAlgorithm.jsonWebSignature2020.rawValue,
//            SignatureAlgorithm.rsaSignature2018.rawValue,
//            SignatureAlgorithm.ed25519Signature2018.rawValue:
//            try validateField(
//                field: vpTokenSigningResult.signedData,
//                fieldPath: ["VPTokenSigningResult", "signedData"],
//                className: className
//            )
//            proof?.jws = vpTokenSigningResult.signedData
//
//        case SignatureAlgorithm.ed25519Signature2020.rawValue:
//            try validateField(
//                field: vpTokenSigningResult.signedData,
//                fieldPath: ["VPTokenSigningResult", "signedData"],
//                className: className
//            )
//            proof?.proofValue = vpTokenSigningResult.signedData
//
//        default:
//            throw UnsupportedSignatureAlgorithm(
//                message: "Unsupported algorithm: \(signatureSuite)",
//                className: className
//            )
//        }
//
//        let ldpVPToken = LdpVPToken(
//            context: unsignedLdpVPToken.context,
//            type: unsignedLdpVPToken.type,
//            verifiableCredential: unsignedLdpVPToken.verifiableCredential,
//            id: unsignedLdpVPToken.id,
//            holder: unsignedLdpVPToken.holder,
//            proof: proof!
//        )
//        let descriptorMaps = credentialInputDescriptorMappings.map { mapping in
//            DescriptorMap(
//                id: mapping.inputDescriptorId,
//                format: .ldp_vp,
//                path: createDescriptorMapPath(rootIndex),
//                pathNested: createNestedPath(
//                    id: mapping.inputDescriptorId,
//                    nestedPath: mapping.nestedPath,
//                    format: .ldp_vc
//                )
//            )
//        }
//        return ([ldpVPToken], descriptorMaps, rootIndex + 1)
//    }
}
