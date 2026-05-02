import Foundation

class JsonLd {
    static var canonicalizer: JsonLdCanonicalizerCallback? = nil
    static var normalizer: JsonLdNormalizerCallback? = nil
    
    static func setCanonicalizer(_ callback: JsonLdCanonicalizerCallback?) {
        JsonLd.canonicalizer = callback
    }
    
    static func normalizeCredential(_ credential: AnyCodable) throws -> Data {
        guard var parsedCredential = credential.value as? [String: Any] else {
            throw InvalidData(message: "Credential value is not right", className: String(describing: JsonLd.self))
        }
        
        let proofConfig = parsedCredential["proof"] as? [String: Any]
        
        parsedCredential.removeValue(forKey: "proof")
        
        let unsecuredDocument = parsedCredential
        
        // TODO: Finish the logic
        // transformedDocumentHash = normalize(unsecuredDocument)
        // proofConfigHash = normalize(proofConfig)
        // hashData = transformedDocumentHash + proofConfigHash
        // return hashData
        return Data()
    }
}
