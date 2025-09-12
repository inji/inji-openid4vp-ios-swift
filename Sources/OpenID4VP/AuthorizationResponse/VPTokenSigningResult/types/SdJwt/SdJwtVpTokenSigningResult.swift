import Foundation

public struct SdJwtVpTokenSigningResult : VPTokenSigningResult {
    let uuidToKbJWTSignature : [String: String]
}
