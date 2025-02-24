import Foundation
import CryptoKit
import JSONWebSignature

struct JWTHandler {
    static let className = String(describing: JWTHandler.self)
    
    private let jwt : String
    private let publicKeyResolver: PublicKeyResolver
    
    init(jwt: String, publicKeyResolver: PublicKeyResolver) {
        self.jwt = jwt
        self.publicKeyResolver = publicKeyResolver
    }
    
    func verify() async throws {
        do {
            // TODO: keyResolver.resolveKey should return publicKey instead of String once multiple signature support is added
            let publicKey = try await publicKeyResolver.resolveKey(header: try extractDataJsonFromJwt(jwtToken: jwt, jwtPart: .header))
            
            let base64PublicKey = Base64Decoder.makeBase64Standard(publicKey)
            
            guard let publicKeyData = Data(base64Encoded: base64PublicKey) else {
                throw Logger.handleException(exceptionType: "JsonDecodingFailed", message: "Did public key decoding failed", className: JWTHandler.className)
            }
            do {
                let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
                
                let jws = try JWS(jwsString: jwt)
                guard try jws.verify(key: publicKey) else {
                    throw Logger.handleException(exceptionType: "InvalidSignature", message: "Jwt proof verification failed",className: JWTHandler.className)
                }
            }
        } catch {
            throw Logger.handleException(exceptionType: "ProofVerificationFailed", message: error.localizedDescription,className: JWTHandler.className)
        }
    }
}

