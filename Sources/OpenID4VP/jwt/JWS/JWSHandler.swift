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
            let publicKey = try await publicKeyResolver.resolveKey(header: try extractDataJsonFromJws(jwsPart: .header))

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

