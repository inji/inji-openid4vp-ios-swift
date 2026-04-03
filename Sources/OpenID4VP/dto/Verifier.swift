import Foundation

public struct Verifier {
    public let clientId: String
    public let responseUris: [String]
    public let jwksUri: String?
    public let allowUnsignedRequest: Bool
    // specification version that the verifier supports, default is v1
    public let specVersion: SpecVersion

    public init(clientId: String, responseUris: [String], jwksUri: String? = nil, allowUnsignedRequest: Bool = false, specVersion: SpecVersion = .v1) {
        self.clientId = clientId
        self.responseUris = responseUris
        self.jwksUri = jwksUri
        self.allowUnsignedRequest = allowUnsignedRequest
        self.specVersion = specVersion
    }
}
