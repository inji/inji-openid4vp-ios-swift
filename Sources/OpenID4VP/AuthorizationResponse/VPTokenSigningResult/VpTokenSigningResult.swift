import Foundation

public struct VPTokenSigningResult: Codable {

    public let signedData: Data

    public init(signedData: Data) {
        self.signedData = signedData
    }
}
