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

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        do {
            self.kty = try container.decode(String.self, forKey: .kty)
            self.use = try container.decode(String.self, forKey: .use)
            self.crv = try container.decode(String.self, forKey: .crv)
            self.x = try container.decode(String.self, forKey: .x)
            self.alg = try container.decode(String.self, forKey: .alg)
            self.kid = try container.decode(String.self, forKey: .kid)
            self.y = try? container.decodeIfPresent(String.self, forKey: .y)
        } catch let error as DecodingError {
            throw DeserializationFailure(fieldPath: ["jwk"], errorMessage: error.localizedDescription, className: JWK.className)

        }
    }

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

        try validateField(y, ["y"], JWK.className)
    }

    enum CodingKeys: String, CodingKey {
        case kty, use, crv, x, alg, kid, y
    }
}
