let DID_RESOLVER = "https://resolver.identity.foundation/1.0/identifiers/"

enum JwtPart: Int {
    case header = 0, payload, signature
}
