import Foundation

struct Format: Codable, Equatable {
    let ldpVc: LdpFormat
    static let className = String(describing: Format.self)
    
    enum CodingKeys: String, CodingKey {
        case ldpVc = "ldp_vc"
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ldpVc = try container.decodeRequired(
            LdpFormat.self,
            forKey: .ldpVc,
            fieldPath: ["format", "ldp_vc"],
            className: Format.className,
            isMandatory: true
        )!
    }
    
    func validate() throws {
        try ldpVc.validate()
    }
    
    static func == (lhs: Format, rhs: Format) -> Bool {
        return lhs.ldpVc == rhs.ldpVc
    }
}
