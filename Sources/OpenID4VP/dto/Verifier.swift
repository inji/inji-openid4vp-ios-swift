import Foundation

public struct Verifier {
    public let clientId: String
    public let responseUris: [String]
    public let clientMetadata: ClientMetadata?

    public init(clientId: String, responseUris: [String], clientMetadata: ClientMetadata? = nil) {
        self.clientId = clientId
        self.responseUris = responseUris
        self.clientMetadata = clientMetadata
    }
}
