import Foundation

public struct UnsignedVPToken: Codable {

    public let format: FormatType
    public let holderKeyReference: String
    public let signatureAlgorithm: String
    // Base64 encoded byte array of the actual data to sign
    public let dataToSign: Data

    public init(
        format: FormatType,
        holderKeyReference: String,
        signatureAlgorithm: String,
        dataToSign: Data
    ) {
        self.format = format
        self.holderKeyReference = holderKeyReference
        self.signatureAlgorithm = signatureAlgorithm
        self.dataToSign = dataToSign
    }
}

