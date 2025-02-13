import Foundation

public enum ClientIdScheme: String, Codable{
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "did"
}

enum ResponseMode: String, Codable{
    case directPost = "direct_post"
    case directPostJwt = "direct_post.jwt"
}
