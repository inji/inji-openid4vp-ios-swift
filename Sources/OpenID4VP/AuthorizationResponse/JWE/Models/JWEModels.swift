
struct JWEEncryptionConfig {
    let alg: String
    let enc: String
}

struct JWKS: Codable {
    let keys: [JWK]
    static let className = String(describing: JWKS.self)
    
    func validate() throws {
        for (index, key) in keys.enumerated() {
            do {
                try key.validate()
            } catch {
                throw Logger.handleException(exceptionType: "InvalidJwksInput", fieldPath: ["jwks", "keys", "\(index)"], className: JWKS.className )
            }
        }
    }
}

public struct JWK: Codable {
    let kty: String
    let use: String
    let crv: String
    let x: String
    let alg: String
    let kid: String
    var y: String? = nil
    static let className = String(describing: JWK.self)
    
    func validate() throws {
        let requiredFields: [(String, String)] = [
            (kty, "kty"),
            (use, "use"),
            (crv, "crv"),
            (x, "x"),
            (alg, "alg"),
            (kid, "kid")
        ]

        for (value, fieldName) in requiredFields {
            try validateField(value, fieldName: fieldName)
        }
        
        if let y = y {
            try validateField(y, fieldName: "y")
        }
    }
}
