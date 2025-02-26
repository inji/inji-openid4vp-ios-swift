import Foundation



enum DidResolverExceptions: Error, Equatable, LocalizedError {
    case unsupportedDidUrl(message: String?)
    case didResolutionFailed(message: String?)
    
    public var errorDescription: String? {
        switch self {
        case .unsupportedDidUrl(let message):
            return message ?? "Given did url is not supported"
        case .didResolutionFailed(message: let message):
            return "Failed to resolve did due to \(message ?? "unknown error")"
        }
    }
}
