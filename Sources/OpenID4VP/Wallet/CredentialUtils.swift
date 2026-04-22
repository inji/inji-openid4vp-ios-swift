import Foundation

func extractSdJwtPayload(_ credential: AnyCodable, className: String) throws -> (Credential: String, payload: [String: Any]) {
    let sdJwtCredential = try extractSDJwtString(from: credential, className: className)
    
    guard let sdJWT = sdJwtCredential.split(separator: "~").first else {
        throw InvalidData(message: "SD-JWT credential is malformed or empty", className: className)
    }
    let sdJwtPayload = try JWSHandler.extractDataJsonFromJws(jws: String(sdJWT), jwsPart: .payload)
    
    return (sdJwtCredential, sdJwtPayload)
}

func extractSDJwtString(from credential: AnyCodable, className: String) throws -> String {
    guard let sdJwtCredential = credential.value as? String else {
        throw InvalidData(message: "SD-JWT credential is not a String", className: className)
    }
    return sdJwtCredential
}
