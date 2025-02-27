import Foundation

public enum ClientIdScheme: String, Codable{
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "did"
}

public enum ResponseMode: String, Codable, Equatable{
    case directPost = "direct_post"
}
