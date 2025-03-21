import Foundation

public enum ClientIdScheme: String {
    case preRegistered = "pre-registered"
    case redirectUri = "redirect_uri"
    case did = "did"
}

public enum ResponseMode: String {
    case directPost = "direct_post"
    case directPostJwt = "direct_post.jwt"
}


enum ResponseType: String {
    case vp_token = "vp_token"
}
