import Foundation

public enum ClientIdPrefix: String, Codable, CaseIterable {
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "decentralized_identifier"
    
    public static func fromValue(_ value: String) -> ClientIdPrefix? {
        return ClientIdPrefix(rawValue: value)
    }
}
