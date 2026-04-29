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
        guard let holder = holder else {
            throw InvalidData(message: "Holder is required for LDP VP Tokens", className: className)
        }
        
        guard let signatureSuite = signatureSuite else {
            throw InvalidData(message: "Signature suite is required for LDP VP Tokens", className: className)
        }
        
        var context: [String] = ["https://www.w3.org/2018/credentials/v1"]
        if signatureSuite == SignatureAlgorithm.ed25519Signature2020.rawValue {
            context.append("https://w3id.org/security/suites/ed25519-2020/v1")
        } else if signatureSuite == SignatureAlgorithm.jsonWebSignature2020.rawValue {
            context.append("https://w3id.org/security/suites/jws-2020/v1")
        }
        
        var verifiableCredentials: [AnyCodable] = []
        
        for index in 0..<credentialInputDescriptorMappings.count {
            let mapping = credentialInputDescriptorMappings[index]
            verifiableCredentials.append(mapping.credential)
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: mapping.format, credential: mapping.credential, inputDescriptorId: mapping.inputDescriptorId,
                nestedPath: "$.\(Self.internalPath)[\(index)]"
            )
        }
        
        let proof = Proof(
            type: signatureSuite,
            created: nil,
            challenge: authorizationRequest.nonce,
            domain: authorizationRequest.clientId,
            verificationMethod: holder, proofValue: nil
        )
        
        let vpTokenSigningPayload = LdpVPToken(
            context: context,
            type: ["VerifiablePresentation"],
            verifiableCredential: verifiableCredentials,
            id: id,
            holder: holder,
            proof: proof
        )
        
        guard let dataToSign = try? JSONEncoder().encode(vpTokenSigningPayload),
              let jsonString = String(data: dataToSign, encoding: .utf8) else {
            throw InvalidData(message: "Failed to encode LdpVPToken for signing.", className: className)
        }
        
        let unsignedVPToken = UnsignedVPToken(
            format: .ldp_vc,
            holderKeyReference: holder,
            signatureAlgorithm: signatureSuite,
            dataToSign: jsonString
        )
        
        return (vpTokenSigningPayload, [unsignedVPToken])
    }
    
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        guard let authorizationRequest = authorizationRequest as? AuthorizationDcqlRequest else {
            throw InvalidData(message: "Expected AuthorizationDcqlRequest for DCQL flow", className: className)
        }
        var unsignedVPTokens: [UnsignedVPToken] = []
        var vpTokenSigningPayload : [String: LdpVPToken] = [:]
        
        for index in 0..<credentialToCredentialQueryIdMappings.count {
            var credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings[index]
            let uuid = UUIDGenerator.generateUUID()
            
            credentialToCredentialQueryIdMapping.identifier = uuid
            credentialToCredentialQueryIdMappings[index] = credentialToCredentialQueryIdMapping
            
            let (credential, credentialQueryId) = (credentialToCredentialQueryIdMapping.credential, credentialToCredentialQueryIdMapping.credentialQueryId)
            
            var context: [String] = ["https://www.w3.org/2018/credentials/v1"]
            
            let verifiableCredentials: [AnyCodable] = [credential]
            
            let mappedCredentialQuery = try authorizationRequest.dcqlQuery.credentials.first(where: { $0.id == credentialQueryId }) ?? {
                throw InvalidData(message: "No matching credential query found for credential query id: \(credentialQueryId)", className: className)
            }()
            
            
            if(mappedCredentialQuery.requireCryptographicHolderBinding) {
                let (signatureSuite, holder, holderKeyAlg) = try extractHolderAndSignatureSuite(credential)
                
                context.append("https://w3id.org/security/suites/jws-2020/v1")
                
                let proof = Proof(
                    type: signatureSuite,
                    created: nil,
                    challenge: authorizationRequest.nonce,
                    domain: authorizationRequest.clientId,
                    verificationMethod: holder,
                    proofValue: nil
                )
                
                let unsignedLdpVpToken: LdpVPToken = LdpVPToken(
                    context: context,
                    type: ["VerifiablePresentation"],
                    verifiableCredential: verifiableCredentials,
                    id: id,
                    holder: holder,
                    proof: proof
                )
                vpTokenSigningPayload[uuid] = unsignedLdpVpToken
                guard let dataToSign = try? JSONEncoder().encode(unsignedLdpVpToken),
                      let jsonString = String(data: dataToSign, encoding: .utf8) else {
                    throw InvalidData(message: "Failed to encode LdpVPToken for signing.", className: className)
                }
                
                guard let jsonLdCanonicalizer = JsonLd.canonicalizer else {
                    throw InvalidData(message: "Failed to get JsonLd canonicalizer.", className: className)
                }
                
                let jwsPayload = try await jsonLdCanonicalizer(AnyCodable(jsonString))
                let jwsHeader = try base64URLEncode([
                    "alg": holderKeyAlg,
                    "crit" : ["b64"],
                    "b64": false
                ])
                let preHash = "\(jwsHeader).\(jwsPayload)"
                
                let unsignedVPToken = UnsignedVPToken(
                    format: .ldp_vc,
                    holderKeyReference: holder,
                    signatureAlgorithm: signatureSuite,
                    dataToSign: preHash
                )
                
                unsignedVPTokens.append(unsignedVPToken)
            } else {
                vpTokenSigningPayload[uuid] = LdpVPToken(
                    context: context,
                    type: ["VerifiablePresentation"],
                    verifiableCredential: verifiableCredentials,
                    id: id
                )
            }
            
        }
        
        return (vpTokenSigningPayload, unsignedVPTokens)
    }
    
    private func extractHolderAndSignatureSuite(_ credential: AnyCodable) throws -> (holder: String, signatureSuite: String, holderKeyAlg: String) {
        guard let credentialDict = credential.value as? [String: Any] else {
            throw InvalidData(message: "Credential is not a valid JSON object", className: className)
        }
        
        guard let credentialSubject = credentialDict["credentialSubject"] as? [String: Any], let holderId = credentialSubject["id"] as? String else {
            throw InvalidData(message: "Holder ID not available in the credential", className: className)
        }
        
        // extract key alg from holderId
        let holderKeyAlgorithm = getJWSAlgorithm(from: holderId)
        
        
        return (holder: holderId, signatureSuite: SignatureAlgorithm.jsonWebSignature2020.rawValue, holderKeyAlg: holderKeyAlgorithm)
    }
}
