import Foundation

private let className = "UnsignedLdpVPTokenBuilder"

public class UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let verifiableCredential: [AnyCodable]
    private let id: String
    private let holder: String
    private let challenge: String
    private let domain: String
    private let signatureSuite: String
    
    static let internalPath: String = "verifiableCredential"
    
    public init(
        verifiableCredential: [AnyCodable],
        id: String,
        holder: String,
        challenge: String,
        domain: String,
        signatureSuite: String
    ) {
        self.verifiableCredential = verifiableCredential
        self.id = id
        self.holder = holder
        self.challenge = challenge
        self.domain = domain
        self.signatureSuite = signatureSuite
    }
    
    public func build() -> [String: Any] {
        var context: [String] = ["https://www.w3.org/2018/credentials/v1"]
        if signatureSuite == SignatureAlgorithm.ed25519Signature2020.rawValue {
            context.append("https://w3id.org/security/suites/ed25519-2020/v1")
        } else if signatureSuite == SignatureAlgorithm.jsonWebSignature2020.rawValue {
            context.append("https://w3id.org/security/suites/jws-2020/v1")
        }
        
        let proof = Proof(
            type: signatureSuite,
            created: nil,
            challenge: challenge,
            domain: holder,
            verificationMethod: holder, proofValue: nil
        )
        
        let vpTokenSigningPayload = LdpVPToken(
            context: context,
            type: ["VerifiablePresentation"],
            verifiableCredential: verifiableCredential,
            id: id,
            holder: holder,
            proof: proof
        )
        
        guard let dataToSign = try? JSONEncoder().encode(vpTokenSigningPayload),
              let jsonString = String(data: dataToSign, encoding: .utf8) else {
            print("Failed to encode LdpVPToken for signing.")
            return [:]
        }
        
        return [
            "unsignedVPToken": UnsignedLdpVPToken(dataToSign:jsonString),
            "vpTokenSigningPayload": vpTokenSigningPayload
        ]
    }
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (payload: Any?, unsignedVPToken: any UnsignedVPToken) {
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
            challenge: challenge,
            domain: holder,
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
        
        return (vpTokenSigningPayload, UnsignedLdpVPToken(dataToSign:jsonString))
    }
}
