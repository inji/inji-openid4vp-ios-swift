import Foundation

struct ResponseModeBasedHandlerFactory {
    static let className = String(describing: ResponseModeBasedHandlerFactory.self)
    
    static func get(responseMode: String?) throws -> ResponseModeBasedHandler {
        switch responseMode {
        case ResponseMode.directPost.rawValue:
            return DirectPostResponseModeHandler()
        case ResponseMode.directPostJwt.rawValue:
            return DirectPostJwtResponseModeHandler()
        default:
            throw InvalidData(
                            message: "Given response_mode - \(responseMode ?? "") is not supported",
                            className: className,
                            code: OpenID4VPErrorCodes.invalidRequest
                        )
        }
    }
}
