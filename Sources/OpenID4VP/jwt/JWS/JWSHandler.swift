import Foundation
import CryptoKit
import JSONWebSignature
import Base58Swift

struct JWSHandler {
    static let className = String(describing: JWSHandler.self)
    
    static func verify(jws: String, publicKey: PublicKeyType) async throws {
        do {
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
    
    static func createUnsignedJWS(header: [String: Any], payload: [String: Any]) throws -> String {
        do {
            let headerEncoded = try jsonCompactString(header)
            let payloadEncoded = try jsonCompactString(payload)

            return "\(headerEncoded).\(payloadEncoded)"
        } catch {
            throw GenericFailure(message: "JWS creation failed: \(error.localizedDescription)", className: JWSHandler.className)
        }
    }
    
//    private static func jsonCompactString(_ input : [String: Any]) throws -> String {
//        let data = try JSONSerialization.data(
//            withJSONObject: input,
//                options: [.sortedKeys] // keep deterministic order
//            )
//            guard let str = String(data: data, encoding: .utf8) else {
//                throw NSError(domain: "JWTEncoding", code: -1, userInfo: [NSLocalizedDescriptionKey: "UTF8 conversion failed"])
//            }
//        return Data(str.utf8).toBase64UrlEncoded()
//    }
    
    private static func jsonCompactString(_ input: [String: Any]) throws -> String {
        let data = try JSONSerialization.data(
            withJSONObject: input,
            options: [.withoutEscapingSlashes] // Remove .sortedKeys - JS doesn't sort by default
        )
        
        // Ensure no extra whitespace (JS default)
        guard let str = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "JWTEncoding", code: -1, userInfo: [NSLocalizedDescriptionKey: "UTF8 conversion failed"])
        }
        
        // Additional cleanup to match JS exactly
        let compactStr = str.replacingOccurrences(of: " ", with: "")
        
        return Data(compactStr.utf8).toBase64UrlEncoded()
    }
    
    static func extractDataJsonFromJws(jws: String, jwsPart: JWSPart) throws -> [String:Any] {
        let components = jws.split(separator: ".")
        let payload = String(components[jwsPart.rawValue])
        return try Base64Decoder.decodeBase64ToJSON(payload)
    }
}

