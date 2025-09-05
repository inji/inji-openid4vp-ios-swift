import Foundation

public enum FormatType: String, Codable {
    case ldp_vc = "ldp_vc"
    case mso_mdoc = "mso_mdoc"
    case sdJWT = "sd-jwt"
    
    public static func fromValue(_ value: String) -> FormatType? {
        return FormatType(rawValue: value)
    }
}
