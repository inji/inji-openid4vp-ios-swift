import Foundation

public struct VPTokenSigningResult: Codable {

    public let signedData: String

    public init(signedData: String) {
        self.signedData = signedData
    }
}
