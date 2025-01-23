import Foundation
import CryptoKit
import JSONWebSignature

struct DidHandler: JwtProofTypeHandler {
    static let className = String(describing: DidHandler.self)
    
    func verify(jwtToken: String, clientId: String, networkManager: NetworkManaging) async throws {
        
        let host = "\(DID_RESOLVER)\(clientId)"
        
        guard let url = URL(string: host ) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed",message: "Url creation for did resolution failed" ,className: DidHandler.className)
        }
        
        let response = (try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.GET, bodyParams: nil, headers: nil))!
        
        guard let kid = extractKid(from: jwtToken) else {
            throw Logger.handleException(
                exceptionType: "KidExtractionFailed",
                message: "Kid extraction from did document failed",
                className: DidHandler.className
            )
        }
        try verifyJWT(jwt: jwtToken, publicKey: extractPublicKeyMultibase(for: kid, from: response)!)
    }
    
    func verifyJWT(jwt: String, publicKey: String) throws {
        do {
            
            let base64PublicKey = makeBase64Standard(publicKey)
            
            guard let publicKeyData = Data(base64Encoded: base64PublicKey) else {
                throw Logger.handleException(exceptionType: "JsonDecodingFailed", message: "Did public key decoding failed", className: DidHandler.className)
            }
            do {
                let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
                
                let jws = try JWS(jwsString: jwt)
                guard try jws.verify(key: publicKey) else {
                    throw Logger.handleException(exceptionType: "InvalidSignature", message: "Jwt proof verification failed",className: DidHandler.className)
                }
            }
        } catch {
            throw Logger.handleException(exceptionType: "ProofVerificationFailed", message: error.localizedDescription,className: DidHandler.className)
        }
    }
}
