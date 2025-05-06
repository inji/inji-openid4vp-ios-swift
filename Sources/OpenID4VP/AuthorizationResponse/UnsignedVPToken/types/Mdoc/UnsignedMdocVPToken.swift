import SwiftCBOR
import Foundation

public struct UnsignedMdocVPToken: Codable, UnsignedVPToken {
    // map of docType to deviceAuthenticationBytes which will be used as payload for signing
    let deviceAuthenticationBytes : [String : String]
}
