import Foundation

struct Format: Codable {
    let ldpVc: LdpFormat
    
    enum CodingKeys: String, CodingKey {
        case ldpVc = "ldp_vc"
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ldpVc = try container.decodeIfPresent(LdpFormat.self, forKey: .ldpVc)!
    }
    
    func validate() throws {
        try ldpVc.validate()
    }
}
