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
    
    static func createAuthorizationRequestObject(
        clientIdScheme: ClientIdScheme,
        authorizationRequestParams: [String: Any],
        jwtHeaderData: [String: Any]? = jwtHeader,
        applicableFields: [String]? = nil,
        addValidSignature: Bool = true
    ) -> String {
        var queryParams = authorizationRequestParams
        
        func addAsJSONParam(_ paramName: String) {
            if let data = queryParams[paramName],
               let jsonData = try? JSONSerialization.data(withJSONObject: data, options: []),
               let jsonString = String(data: jsonData, encoding: .utf8) {
                queryParams[paramName] = jsonString
            }
            
        }
        // Convert presentation_definition & client_metadata to JSON string if provided
        addAsJSONParam("presentation_definition")
        addAsJSONParam("client_metadata")
        var authorizationRequestParam = [String: String]()
        
        
        let listOfApplicableFieldsOfClientIdScheme = (applicableFields==nil) ? authRequestClientIdSchemeMap[clientIdScheme]!: applicableFields
        for fieldName in listOfApplicableFieldsOfClientIdScheme! {
            if let value = queryParams[fieldName] {
                authorizationRequestParam[fieldName] = value as? String
            }
        }
        
        
        if clientIdScheme == .did {
            let privateKeyData = Data(base64Encoded: ed25519PrivateKey)
            let headerData = try? JSONSerialization.data(withJSONObject: jwtHeaderData as Any)
            let header64 = base64UrlEncode(headerData!)
            let payloadData = try? JSONSerialization.data(withJSONObject: authorizationRequestParam)
            let payload64 = base64UrlEncode(payloadData!)
            let message = "\(header64).\(payload64)".data(using: .utf8)!
            
            let signature64: String
            if addValidSignature, let validSignature = signEd25519(privateKey: privateKeyData!, message: message) {
                signature64 = validSignature
            } else {
                signature64 = "aW52YWxpZC1zaWdu"
            }
            return "\(header64).\(payload64).\(signature64)"
        } else {
            return encodeB64(try! JSONSerialization.data(withJSONObject: authorizationRequestParam).base64EncodedString())
        }
    }
}

