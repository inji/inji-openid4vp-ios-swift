import Foundation
import CryptoKit
import JSONWebSignature

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
            
            let base64PublicKey = Base64Decoder.makeBase64Standard(publicKey)
            
            guard let publicKeyData = Data(base64Encoded: base64PublicKey) else {
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
                        message: "JWS proof verification failed",
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

