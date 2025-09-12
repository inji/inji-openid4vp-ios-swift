import SwiftCBOR
import Foundation

public struct UnsignedSdJwtVPToken: Codable, UnsignedVPToken {
    let uuidToUnsignedKBT : [String : String]
    
    public init(uuidToUnsignedKBT: [String : String]) {
        self.uuidToUnsignedKBT = uuidToUnsignedKBT
    }
}
