import SwiftCBOR
import Foundation

struct UnsignedSdJWTVPToken: Codable, UnsignedVPToken {
    let uuidToUnsignedKBT : [String : String]
}
