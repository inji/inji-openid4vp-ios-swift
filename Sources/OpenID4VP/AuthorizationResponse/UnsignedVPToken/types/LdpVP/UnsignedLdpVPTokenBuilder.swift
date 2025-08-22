import Foundation

public class UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let verifiableCredential: [AnyCodable]
    private let id: String
    private let holder: String
    private let challenge: String
    private let domain: String
    private let signatureSuite: String

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
}
