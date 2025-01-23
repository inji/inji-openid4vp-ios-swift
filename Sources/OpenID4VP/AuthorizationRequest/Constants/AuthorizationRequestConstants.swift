import Foundation

enum ClientIdScheme: String, Codable{
    case preRegistered = "pre_registered"
    case redirectUri = "redirect_uri"
    case did = "did"
}
