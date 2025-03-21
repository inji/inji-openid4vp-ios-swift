import Foundation
import Alamofire

public typealias HttpMethod = HTTPMethod

enum Header : String {
    case contentType = "Content-Type"
}


public enum ContentTypes : String {
    case applicationJson = "application/json"
    case applicationJwt = "application/oauth-authz-req+jwt"
    case applicationFormUrlEncoded = "application/x-www-form-urlencoded"
}
