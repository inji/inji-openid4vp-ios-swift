import Foundation

public enum VPFormatType: String, Codable {
    case ldp_vp = "ldp_vp"
    case ldp_vc = "ldp_vc"
    case mso_mdoc = "mso_mdoc"
    
    public static func fromValue(_ value: String) -> VPFormatType? {
        return VPFormatType(rawValue: value)
    }
}
