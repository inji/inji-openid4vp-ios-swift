import Foundation

struct LdpFormat: Codable {
    let proofType: [String]
    static let className = String(describing: LdpFormat.self)
    
    enum CodingKeys: String, CodingKey {
        case proofType = "proof_type"
    }
    
    func validate() throws {
        guard !proofType.isEmpty else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["ldpFormat","proof_type"], className: LdpFormat.className)
        }
    }
}
