import Foundation
import SwiftCBOR

private let className = "CredentialUtils"

func expandCredentialTag(_ credential: Credential) throws -> TaggedCredential {
    switch credential.format {
    case .ldp_vc:
        guard let credentialData = credential.data.value as? [String:Any] else {
            throw InvalidData(message: "Credential data is not in the expected format", className: className)
        }
        let credentialSubjectId: String? = (credentialData["credentialSubject"] as? [String:Any] ?? [:])["id"] as? String
        return W3cTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: credentialSubjectId != nil,
            types: credentialData["type"] as? [String] ?? []
        )
    case .mso_mdoc:
        guard let mdocCredential = credential.data.value as? String else {
            throw InvalidData(
                message: "MDOC credential is not a String",
                className: AuthorizationResponseHandler.className
            )
        }
        guard let decodedCredential = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
            throw InvalidData(
                message: "Invalid Verifiable Credential: Error while decoding credential",
                className: className
            )
        }
        
        guard let docType = getValueFromCBORMap(cborMap: decodedCredential, key: "docType"),
              let docTypeString = extractStringFromCBOR(docType) else {
            throw InvalidData(
                message: "docType missing or invalid in credential",
                className: className
            )
        }
        
        return MdocTaggedCredential(
            hasCryptographicHolderBinding: true,
            doctype: docTypeString
        )
    case .dc_sd_jwt, .vc_sd_jwt:
        guard let sdJwtCredential = credential.data.value as? String else {
            throw InvalidData(
                message: "SD-JWT credential is not a String",
                className: className
            )
        }
        
        let sdJWT = sdJwtCredential.split(separator: "~")[0]
        let sdJWTPayload = try JWSHandler.extractDataJsonFromJws(jws: String(sdJWT), jwsPart: .payload)
        
        return SdJwtTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: true,
            vct: sdJWTPayload["vct"] as? String ?? ""
        )
    }
}


func convertToProcessedCredentials(_ filteredWalletCredentialIds: [String], _ credentialIdToCredential: [String: Credential]) throws -> [String: any ProcessedCredential] {
    var processedCredentials: [String: any ProcessedCredential] = [:]
    
    for credentialId in filteredWalletCredentialIds {
        guard let credential = credentialIdToCredential[credentialId] else { continue }
        
        switch credential.format {
        case .ldp_vc:
            guard let credentialData = credential.data.value as? [String:Any] else {
                throw InvalidData(message: "Credential data is not in the expected format", className: className)
            }
            
            processedCredentials[credentialId] = (W3cProcessedCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: credentialData
            ))
            
        case .mso_mdoc:
            guard let mdocCredential = credential.data.value as? String else {
                throw InvalidData(message: "MDOC credential is not a String", className: className)
            }
            guard let decodedCredential = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw InvalidData(message: "Invalid Verifiable Credential: Error while decoding credential", className: className)
            }
            
            var namespaces: [String: [String: Any]] = [:]
            if let issuerSignedCBOR = getValueFromCBORMap(cborMap: decodedCredential, key: "issuerSigned"),
               let nameSpacesCBOR = getValueFromCBORMap(cborMap: issuerSignedCBOR, key: "nameSpaces") {
                
                if case let .map(items) = nameSpacesCBOR {
                    for (nsKey, nsValue) in items {
                        if let nsString = extractStringFromCBOR(nsKey), case let .array(elementItems) = nsValue {
                            var elements: [String: Any] = [:]
                            for item in elementItems {
                                if case let .tagged(tag, .byteString(bstr)) = item, tag.rawValue == 24,
                                   let decodedItem = try? CBOR.decode(bstr) {
                                    
                                    if let elementIdCBOR = getValueFromCBORMap(cborMap: decodedItem, key: "elementIdentifier"),
                                       let elementId = extractStringFromCBOR(elementIdCBOR),
                                       let elementValueCBOR = getValueFromCBORMap(cborMap: decodedItem, key: "elementValue") {
                                        
                                        if let unwrappedValue = unwrapCbor(elementValueCBOR) {
                                            elements[elementId] = unwrappedValue
                                        }
                                    }
                                }
                            }
                            namespaces[nsString] = elements
                        }
                    }
                }
            }
            
            processedCredentials[credentialId] = (MdocProcessedCredential(
                credentialId: credential.credentialId,
                namespaces: namespaces
            ))
            
        case .dc_sd_jwt, .vc_sd_jwt:
            guard let sdJwtCredential = credential.data.value as? String else {
                throw InvalidData(message: "SD-JWT credential is not a String", className: className)
            }
            
            let sdJWT = sdJwtCredential.split(separator: "~")[0]
            let sdJWTPayload = try JWSHandler.extractDataJsonFromJws(jws: String(sdJWT), jwsPart: .payload)
            
            let claims = sdJWTPayload["credentialSubject"] as? [String: Any] ?? sdJWTPayload
            
            processedCredentials[credentialId] = (SdJwtProcessedCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: claims
            ))
        }
    }
    
    return processedCredentials
}
