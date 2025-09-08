import SwiftCBOR
import Foundation

//TODO: check on the usage of SdJWT or SdJwt
struct UnsignedSdJWTVPToken: Codable, UnsignedVPToken {
    let uuidToUnsignedKBT : [String : String]
}
