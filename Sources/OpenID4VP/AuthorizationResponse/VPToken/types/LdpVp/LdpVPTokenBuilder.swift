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
        let ldpVPToken = try buildVPToken(
            getUnsignedLdpVPToken: unsignedVPTokenResult.vpTokenSigningPayload as? LdpVPToken,
            addCryptographicHolderBinding: true,
            getVPTokenSigningResult: vpTokenSigningResults.first,
            getUnsignedVPToken: unsignedVPTokenResult.unsignedVPTokens.first
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
            
            let ldpVPToken = try buildVPToken(
                getUnsignedLdpVPToken: unsignedVpTokens[credentialToCredentialQueryIdMapping.identifier ?? ""],
                addCryptographicHolderBinding: credentialQuery.requireCryptographicHolderBinding,
                getVPTokenSigningResult: vpTokenSigningResultsIterator.next(),
                getUnsignedVPToken: unsignedVpTokenIterator.next()
            )
            
            vpTokenResult[credentialQuery.id, default: []].append(ldpVPToken)
        }
        
        
        return vpTokenResult
    }
    
    private func buildVPToken(
        getUnsignedLdpVPToken: @autoclosure @escaping () -> LdpVPToken?,
        addCryptographicHolderBinding: Bool = true,
        getVPTokenSigningResult: @autoclosure @escaping () -> VPTokenSigningResult?,
        getUnsignedVPToken: @autoclosure @escaping () -> UnsignedVPToken?
    ) throws -> VPToken {
        guard let unsignedLdpVPToken = getUnsignedLdpVPToken() else {
            throw InvalidData(message: "payload is not available as LdpVPToken", className: className)
        }
        
        var proof = unsignedLdpVPToken.proof
        
        if(addCryptographicHolderBinding) {
            let signatureSuite = proof?.type ?? ""
            
            guard let vpTokenSigningResult = getVPTokenSigningResult() else {
                throw InvalidData(message: "vpTokenSigningResult is missing", className: className)
            }
            
            if(vpTokenSigningResult.signedData.isEmpty) {
                throw InvalidInput(fieldPath: ["VPTokenSigningResult", "signedData"], className: className)
            }

            guard let unsignedVPToken = getUnsignedVPToken() else {
                throw InvalidData(message: "Missing data to sign", className: className)
            }
            
            switch signatureSuite {
            case SignatureSuite.jsonWebSignature2020.rawValue,
                SignatureSuite.ed25519Signature2018.rawValue:
                proof?.jws = getHeader(unsignedVPToken) + ".." + vpTokenSigningResult.signedData.toBase64UrlEncoded()

            case SignatureSuite.rsaSignature2018.rawValue:
                proof?.signatureValue = vpTokenSigningResult.signedData.toBase64UrlEncoded()

            case SignatureSuite.ed25519Signature2020.rawValue:
                proof?.proofValue = BaseEncoding.base58BtcEncode(vpTokenSigningResult.signedData)

            default:
                throw UnsupportedSignatureAlgorithm(
                    message: "Unsupported algorithm: \(signatureSuite)",
                    className: className
                )
            }
        }
        
        let ldpVPToken = LdpVPToken(
            context: unsignedLdpVPToken.context,
            type: unsignedLdpVPToken.type,
            verifiableCredential: unsignedLdpVPToken.verifiableCredential,
            id: unsignedLdpVPToken.id,
            holder: unsignedLdpVPToken.holder,
            proof: proof
        )
        
        return ldpVPToken
    }
    
    private func getHeader(_ unsignedVPToken: UnsignedVPToken) -> String {
        let dataToSign = unsignedVPToken.dataToSign
        let dotIndex = dataToSign.firstIndex(of: 0x2E)
        let headerData = dataToSign.prefix(upTo: dotIndex ?? Data.Index())
        let header = String(data: headerData, encoding: .utf8) ?? ""
        
        return header
    }
}
