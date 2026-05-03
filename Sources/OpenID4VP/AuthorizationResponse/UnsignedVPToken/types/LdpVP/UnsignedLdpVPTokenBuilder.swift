import Foundation

private let className = "UnsignedLdpVPTokenBuilder"

class UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let id: String
    private let holder: String?
    private let signatureSuite: String?
    public let specVersion: SpecVersion
    public let authorizationRequest: AuthorizationRequest
    public let walletMetadata: WalletMetadata?
    
    static let internalPath: String = "verifiableCredential"
    
    public init(
        authorizationRequest: AuthorizationRequest,
        specVersion: SpecVersion,
        id: String,
        holder: String? = nil,
        signatureSuite: String? = nil,
        walletMetadata: WalletMetadata? = nil
    ) {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        self.id = id
        self.holder = holder
        self.signatureSuite = signatureSuite
        self.walletMetadata = walletMetadata
    }
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        var verifiableCredentials: [AnyCodable] = []
        
        for index in 0..<credentialInputDescriptorMappings.count {
            let mapping = credentialInputDescriptorMappings[index]
            verifiableCredentials.append(mapping.credential)
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: mapping.format, credential: mapping.credential, inputDescriptorId: mapping.inputDescriptorId,
                nestedPath: "$.\(Self.internalPath)[\(index)]"
            )
        }
        let (vpTokenSigningPayload, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(with: verifiableCredentials, signatureSuite: signatureSuite, holder: holder)
        
        return (vpTokenSigningPayload, unsignedVPToken.map { [$0] } ?? [])
    }
    
    //TODO: change the type to [Any] - list of payloads
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        guard let authorizationRequest = authorizationRequest as? AuthorizationDcqlRequest else {
            throw InvalidData(message: "Expected AuthorizationDcqlRequest for DCQL flow", className: className)
        }
        var unsignedVPTokens: [UnsignedVPToken] = []
        var vpTokenSigningPayloads : [String: LdpVPToken] = [:]
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            var credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            let uuid = UUIDGenerator.generateUUID()
            
            credentialToCredentialQueryIdMapping.identifier = uuid
            credentialToCredentialQueryIdMappings[index] = credentialToCredentialQueryIdMapping
            
            let (credential, credentialQueryId) = (credentialToCredentialQueryIdMapping.credential, credentialToCredentialQueryIdMapping.credentialQueryId)
            
            let verifiableCredentials: [AnyCodable] = [credential]
            
            let mappedCredentialQuery = try authorizationRequest.dcqlQuery.credentials.first(where: { $0.id == credentialQueryId }) ?? {
                throw InvalidData(message: "No matching credential query found for credential query id: \(credentialQueryId)", className: className)
            }()
            
            let result = mappedCredentialQuery.requireCryptographicHolderBinding ? try extractHolderAndSignatureSuite(credential) : nil
            
            let (vpTokenSigningPayload, unsignedVPToken) = try await buildPayloadAndUnsignedVPToken(
                with: verifiableCredentials,
                signatureSuite: result?.signatureSuite,
                holder: sanitize(result?.holder),
                addCryptograhicHolderBinding: mappedCredentialQuery.requireCryptographicHolderBinding
            )
            
            vpTokenSigningPayloads[uuid] = vpTokenSigningPayload
            if let unsignedVPToken = unsignedVPToken {
                unsignedVPTokens.append(unsignedVPToken)
            }
            
        }
        
        return (vpTokenSigningPayloads, unsignedVPTokens)
    }
    
    private func buildPayloadAndUnsignedVPToken(with credentials: [AnyCodable], signatureSuite: String?, holder: String?, addCryptograhicHolderBinding: Bool = true) async throws -> (vpTokenSigningPayload: LdpVPToken, unsignedVPToken: UnsignedVPToken?) {
        var context: [String] = ["https://www.w3.org/2018/credentials/v1"]
        if signatureSuite == SignatureAlgorithm.ed25519Signature2020.rawValue {
            context.append("https://w3id.org/security/suites/ed25519-2020/v1")
        } else if signatureSuite == SignatureAlgorithm.jsonWebSignature2020.rawValue {
            context.append("https://w3id.org/security/suites/jws-2020/v1")
        }
        
        if(addCryptograhicHolderBinding == false) {
            return (
                LdpVPToken(
                    context: context,
                    type: ["VerifiablePresentation"],
                    verifiableCredential: credentials,
                    id: id,
                    holder: holder,
                    proof: nil
                ),
                nil)
        }
        
        guard let holder = holder else {
            throw InvalidData(message: "Holder is required for LDP VP Tokens", className: className)
        }
        
        guard let signatureSuite = signatureSuite else {
            throw InvalidData(message: "Signature suite is required for LDP VP Tokens", className: className)
        }
        
        let proof = {
            addCryptograhicHolderBinding ? Proof(
                type: signatureSuite,
                created: nil,
                challenge: authorizationRequest.nonce,
                domain: authorizationRequest.clientId,
                verificationMethod: holder,
                proofValue: nil
            ) : nil
        }()
        
        let vpTokenSigningPayload = LdpVPToken(
            context: context,
            type: ["VerifiablePresentation"],
            verifiableCredential: credentials,
            id: id,
            holder: holder,
            proof: proof
        )
        
        guard let dataToSign = try? JSONEncoder().encode(vpTokenSigningPayload),
              let jsonString = String(data: dataToSign, encoding: .utf8) else {
            throw InvalidData(message: "Failed to encode LdpVPToken for signing.", className: className)
        }
        
        if(signatureSuite == SignatureAlgorithm.jsonWebSignature2020.rawValue) {
            guard let jsonLdCanonicalizer = JsonLd.canonicalizer else {
                throw InvalidData(message: "Failed to get JsonLd canonicalizer.", className: className)
            }
            
            let canonicalizedData = try await jsonLdCanonicalizer(jsonString)
            let normalizedCredentialData = try Base64Decoder.decodeBase64ToData(canonicalizedData)
            
            let signatureAlgorithm: String = try getJWSAlgorithm(from: holder)
            let jwsHeader = try base64URLEncode([
                "alg": signatureAlgorithm,
                // the payload is not Base64URL-encoded
                "crit" : ["b64"],
                "b64": false
            ])
            let headerBytes = Data(jwsHeader.utf8)
            let dot = Data([0x2E]) // "."
            var signingInput = Data()
            signingInput.append(headerBytes)
            signingInput.append(dot)
            signingInput.append(normalizedCredentialData)

            let unsignedVPToken = UnsignedVPToken(
                format: .ldp_vc,
                holderKeyReference: holder,
                signatureAlgorithm: signatureAlgorithm,
                dataToSign: signingInput
            )
            
            return (vpTokenSigningPayload, unsignedVPToken)
        }
        
        // TODO: For non json web signature suite - how is the data to sign populated - should it be canonicalized or just the JSON string of the VP token?
        let unsignedVPToken = UnsignedVPToken(
            format: .ldp_vc,
            holderKeyReference: holder,
            signatureAlgorithm: signatureSuite,
            dataToSign: Data(jsonString.utf8)
        )
        
        return (vpTokenSigningPayload, unsignedVPToken)
    }
    
    private func extractHolderAndSignatureSuite(_ credential: AnyCodable) throws -> (holder: String, signatureSuite: String) {
        guard let credentialDict = credential.value as? [String: Any] else {
            throw InvalidData(message: "Credential is not a valid JSON object", className: className)
        }
        
        guard let credentialSubject = credentialDict["credentialSubject"] as? [String: Any], let holderId = credentialSubject["id"] as? String else {
            throw InvalidData(message: "Holder ID not available in the credential", className: className)
        }
        
        
        return (holder: holderId, signatureSuite: SignatureAlgorithm.jsonWebSignature2020.rawValue)
    }
    
    private func sanitize(_ holderId: String?) -> String? {
        guard let holderId = holderId else {
            return nil
        }
        return (holderId
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")) + "#0"
    }
}
