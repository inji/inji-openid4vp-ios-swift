import Foundation
import CryptoKit
import JSONWebSignature
import Base58Swift

struct JWSHandler {
    static let className = String(describing: JWSHandler.self)
    
    private let jws : String
    private let publicKeyResolver: PublicKeyResolver
    private let verificationMethodUri: String
    
    init(jws: String, publicKeyResolver: PublicKeyResolver, verificationMethodUri: String) {
        self.jws = jws
        self.publicKeyResolver = publicKeyResolver
        self.verificationMethodUri = verificationMethodUri
    }
    
    //TOOD: accept JWS and public key as parameters for verification
    func verify() async throws {
        do {
            let header = try extractDataJsonFromJws(jwsPart: .header)
            
            let publicKey = try await publicKeyResolver.resolve(uri: verificationMethodUri, keyId: header["kid"] as? String)

            let jws = try JWS(jwsString: jws)

            switch publicKey {
            case .ed25519(let edKey):
                guard try jws.verify(key: edKey) else {
                    throw InvalidSignature(
                        className: JWSHandler.className
                    )
                }
            case .secKey(let secKey):
                guard try jws.verify(key: secKey) else {
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

