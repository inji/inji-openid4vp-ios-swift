import SwiftCBOR

func decodeMdoc(_ credential: AnyCodable, className: String) throws -> (mdocCredential: String, decodedMdoc: CBOR) {
    let mdocCredential = try extractMdocString(from: credential, className: className)
    
    guard let decodedMdoc = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
        throw InvalidData(
            message: "Invalid Verifiable Credential: Error while decoding credential",
            className: className
        )
    }
    
    return (mdocCredential, decodedMdoc)
}

func extractMdocString(from credential: AnyCodable, className: String) throws -> String {
    guard let mdocCredential = credential.value as? String else {
        throw InvalidData(
            message: "MDOC credential is not a String",
            className: AuthorizationResponseHandler.className
        )
    }
    
    return mdocCredential
}

func extractMdocDocType(from decodedCredential: CBOR, className: String) throws -> (docType: CBOR, docTypeString: String) {
    guard let docType = getValueFromCBORMap(cborMap: decodedCredential, key: "docType"),
          let docTypeString = extractStringFromCBOR(docType) else {
        
        throw InvalidData(
            message: "docType missing or invalid in credential",
            className: className
        )
    }
    
    return (docType, docTypeString)
}
