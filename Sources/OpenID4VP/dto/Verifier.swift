import Foundation

public struct Verifier {
    public let clientId: String
    public let responseUris: [String]
    public let jwksUri: String?

    public init(clientId: String, responseUris: [String], jwksUri: String? = nil) {
        self.clientId = clientId
        self.responseUris = responseUris
        self.jwksUri = jwksUri
    }
}
