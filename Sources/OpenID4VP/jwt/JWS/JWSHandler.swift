import Foundation
import CryptoKit
import JSONWebSignature
import Base58Swift

struct JWSHandler {
    static let className = String(describing: JWSHandler.self)
    
    private let jws : String
    private let publicKeyResolver: PublicKeyResolver
    
    init(jws: String, publicKeyResolver: PublicKeyResolver) {
        self.jws = jws
        self.publicKeyResolver = publicKeyResolver
    }
    
    func verify() async throws {
        do {
            // TODO: keyResolver.resolveKey should return publicKey instead of String once multiple signature support is added
            let publicKey = try await publicKeyResolver.resolveKey(header: try extractDataJsonFromJws(jwsPart: .header))
            
            let base58Key = String(publicKey.dropFirst())
            guard let publicKeyData = Base58.base58Decode(base58Key) else {
                throw JsonDecodingFailed(
                    message: "DID public key decoding failed",
                    className: JWSHandler.className
                )
            }
            do {
                let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
                
                let jws = try JWS(jwsString: jws)
                guard try jws.verify(key: publicKey) else {
                    throw InvalidSignature(
                        className: JWSHandler.className
                    )
                }
            }
        } catch {
            throw VerificationFailure(
                message: error.localizedDescription,
                className: JWSHandler.className
            )
        }
    }
    
    
    func extractDataJsonFromJws(jwsPart: JWSPart) throws -> [String:Any] {
        let components = jws.split(separator: ".")
        let payload = String(components[jwsPart.rawValue])
        return try Base64Decoder.decodeBase64ToJSON(payload)
    }
}

