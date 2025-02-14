import Foundation

public enum ClientIdScheme: String, Codable{
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "did"
}
