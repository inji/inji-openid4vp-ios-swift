import Foundation
//import JSONWebKey
//TODO: can we use JWK from jose-swift?

struct JWKS: Codable {
    let keys: [JWK]
    static let className = String(describing: JWKS.self)
    
    func validate() throws {
        for (index, key) in keys.enumerated() {
            do {
                try key.validate()
            } catch {
                throw InvalidInput(fieldPath: ["jwks", "keys", "\(index)"], className: JWKS.className )
            }
        }
    }
}
