import Foundation

struct LdpFormat: Codable, Equatable {
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
    
    static func == (lhs: LdpFormat, rhs: LdpFormat) -> Bool {
        return lhs.proofType == rhs.proofType
    }
}
