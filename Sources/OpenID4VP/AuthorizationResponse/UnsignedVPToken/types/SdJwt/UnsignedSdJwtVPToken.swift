import SwiftCBOR
import Foundation

struct UnsignedSdJwtVPToken: Codable, UnsignedVPToken {
    let uuidToUnsignedKBT : [String : String]
}
