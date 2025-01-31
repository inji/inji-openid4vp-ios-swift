import Foundation

func extractKid(from jwtToken: String) -> String? {
    guard let jwtHeader = extractDataJsonFromJwt(jwtToken, part: .header) else {
        return nil
    }
    return jwtHeader["kid"] as? String
}

func extractPublicKeyMultibase(for kid: String, from json: String) throws -> String? {
    
    guard let data = json.data(using: .utf8) else {
        throw Logger.handleException(exceptionType: "UTF8Encoding", className: DidHandler.className)
    }
    
    do {
        if let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
           let didDocument = json["didDocument"] as? [String: Any],
           let verificationMethod = didDocument["verificationMethod"] as? [[String: Any]] {
            
            for method in verificationMethod {
                if let id = method["id"] as? String, id.hasSuffix(kid),
                   let publicKeyMultibase = method["publicKey"] as? String {
                    return publicKeyMultibase
                }
            }
        } else {
            throw Logger.handleException(exceptionType: "PublicKeyNotFound", className: DidHandler.className)
        }
    }
    return nil
}
