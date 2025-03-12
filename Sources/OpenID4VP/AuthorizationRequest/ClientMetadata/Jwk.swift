import Foundation

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
            try validateField(value, [fieldName], JWK.className)
        }
        
        if let y = y {
            try validateField(y, ["y"], JWK.className)
        }
    }
}
