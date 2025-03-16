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
        from vpResponseMetadata: LdpVPResponseMetadata,
        challenge: String
    ) -> Proof {

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        let createdDateAndTime = formatter.string(from: Date())

        return Proof(
            type: vpResponseMetadata.signatureAlgorithm,
            created: createdDateAndTime,
            challenge: challenge,
            domain: vpResponseMetadata.domain,
            jws: vpResponseMetadata.jws,
            proofPurpose: .vpProofPurpose,
            verificationMethod: vpResponseMetadata.publicKey
        )
    }
}
