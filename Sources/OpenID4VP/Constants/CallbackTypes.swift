// Input: credential
// output: base64url encoded canonicalized JSON-LD string of the data
public typealias JsonLdCanonicalizerCallback = (_ data: AnyCodable) async throws -> String
