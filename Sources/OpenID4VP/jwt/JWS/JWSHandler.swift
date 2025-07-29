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
//
//            let base58Key = String(publicKeyMultibase.dropFirst())
//            guard let publicKeyData = Base58.base58Decode(base58Key) else {
//                throw JsonDecodingFailed(
//                    message: "DID public key decoding failed",
//                    className: JWSHandler.className
//                )
//            }
//
//            let rawPublicKey = publicKeyData.dropFirst(2)
//            guard rawPublicKey.count == 32 else {
//                throw JsonDecodingFailed(
//                    message: "Invalid Ed25519 raw public key length",
//                    className: JWSHandler.className
//                )
//            }
//
//            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawPublicKey)

            let jws = try JWS(jwsString: jws)
            guard try jws.verify(key: publicKey) else {
                throw InvalidSignature(
                    className: JWSHandler.className
                )
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

