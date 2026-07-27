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
    if let issuerAuth = getValueFromCBORMap(cborMap: decodedCredential, key: "issuerAuth"){
        switch issuerAuth {
        case .array(let issuerAuthArray):
            guard issuerAuthArray.count > 2,
                  case let .byteString(msoBytes) = issuerAuthArray[2] else {
                throw InvalidData(
                    message: "issuerAuth payload missing or invalid",
                    className: className
                )
            }
            var decodedMso = try CBORDecoder(input: msoBytes).decodeItem()
            if case let CBOR.tagged(tag, inner)? = decodedMso, tag.rawValue == 24 {
                guard case let CBOR.byteString(innerBytes) = inner else {
                    throw InvalidData(
                        message: "cbor tag 24 inner not bstr",
                        className: className
                    )
                }
                decodedMso = try CBORDecoder(input: innerBytes).decodeItem()
            }
            guard let decodedMso = decodedMso else {
                throw InvalidData(
                    message: "Failed to decode MSO",
                    className: className
                )
            }
            if let docType = getValueFromCBORMap(cborMap: decodedMso, key: "docType"),
               let docTypeString = extractStringFromCBOR(docType) {
                return (docType, docTypeString)
            } else {
                throw InvalidData(
                    message: "docType missing or invalid in issuerAuth",
                    className: className
                )
            }
        default:
            throw InvalidData(
                message: "issuerAuth is not an array",
                className: className
            )
        }
    } else  if let docType = getValueFromCBORMap(cborMap: decodedCredential, key: "docType"),
               let docTypeString = extractStringFromCBOR(docType) {
        return (docType, docTypeString)
    } else {
        throw InvalidData(
            message: "docType missing or invalid in credential",
            className: className
        )
    }
}
