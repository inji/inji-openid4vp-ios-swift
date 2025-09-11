import Foundation

struct SdJwtVpTokenSigningResult : VPTokenSigningResult {
    let uuidToKbJWTSignature : [String: String]
}
