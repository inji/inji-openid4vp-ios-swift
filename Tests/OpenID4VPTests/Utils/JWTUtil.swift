import CryptoKit
import Foundation
import OpenID4VP
import JSONWebSignature

struct JWTUtil {
    private static let ed25519PrivateKey = "vlo/0lVUn4oCEFo/PiPi3FyqSBSdZ2JDSBJJcvbf6o0="
    private static let baseUrl = "https://mock-verifier.com"
    private static let responseUri = "\(baseUrl)/verifier/vp-response"
    private static let publicKeyId = "did:example:123#1"
    
    private static let jwtHeader: [String: Any] = [
        "typ": "oauth-authz-req+jwt",
        "alg": "EdDSA",
        "kid": publicKeyId
    ]
    
    private static func replaceCharactersInB64(_ encodedB64: String) -> String {
        return encodedB64.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=+$", with: "", options: .regularExpression)
    }
    
    private static func encodeB64(_ str: String) -> String {
        let encoded = Data(str.utf8).base64EncodedString()
        return replaceCharactersInB64(encoded)
    }
    
    private static func base64UrlEncode(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=+$", with: "", options: .regularExpression)
    }
    
    private static func signEd25519(privateKey: Data, message: Data) -> String? {
        guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateKey) else {
            return nil
        }
        let signature = (try? privateKey.signature(for: message))!
        return base64UrlEncode(signature)
    }
    
    static func create(header: [String:Any]?,payload: [String:Any],addValidSignature: Bool) -> String{
        let privateKeyData = Data(base64Encoded: ed25519PrivateKey)
        let jwtHeader = header == nil ? self.jwtHeader : header
        let headerData = try? JSONSerialization.data(withJSONObject: jwtHeader as Any)
        let header64 = base64UrlEncode(headerData!)
        let payloadData = try? JSONSerialization.data(withJSONObject: payload)
        let payload64 = base64UrlEncode(payloadData!)
        let message = "\(header64).\(payload64)".data(using: .utf8)!
        
        let signature64: String
        if addValidSignature, let validSignature = signEd25519(privateKey: privateKeyData!, message: message) {
            signature64 = validSignature
        } else {
            signature64 = "aW52YWxpZC1zaWdu"
        }
        return "\(header64).\(payload64).\(signature64)"
    }
}

