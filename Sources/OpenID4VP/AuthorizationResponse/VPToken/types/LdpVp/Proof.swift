import Foundation

struct Proof: Encodable {
    let type: String
    let created: String
    let challenge: String
    let domain: String
    let jws: String
    let proofPurpose: ProofPurpose
    let verificationMethod: String

    static func construct(
        from vpTokenSigningResult: LdpVPTokenSigningResult,
        challenge: String
    ) -> Proof {

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        let createdDateAndTime = formatter.string(from: Date())

        return Proof(
            type: vpTokenSigningResult.signatureAlgorithm,
            created: createdDateAndTime,
            challenge: challenge,
            domain: vpTokenSigningResult.domain,
            jws: vpTokenSigningResult.jws,
            proofPurpose: .vpProofPurpose,
            verificationMethod: vpTokenSigningResult.publicKey
        )
    }
}
