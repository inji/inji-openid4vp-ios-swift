import Foundation

struct LdpFormat: Codable {
    let proofType: [String]
    
    enum CodingKeys: String, CodingKey {
        case proofType = "proof_type"
    }
    
    func validate() throws {
        guard !proofType.isEmpty else {
            Logger.error("LdpFormat : proof_type should not be empty.")
            throw AuthorizationRequestException.invalidInput(fieldName: "proof_type")
        }
    }
    
}
