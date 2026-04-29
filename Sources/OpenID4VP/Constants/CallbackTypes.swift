// Input: VP with no signature in stringified JSON
// output: base64url encoded canonicalized JSON-LD string of the data
public typealias JsonLdCanonicalizerCallback = (_ data: String) async throws -> String
