import Foundation
import SwiftCBOR

private let className = "CredentialUtils"

func expandCredentialTags(_ credentialIdToCredential: [String: Credential]) throws -> [String: TaggedCredential] {
   var credentialIdToTags : [String: TaggedCredential] = [:]
   
   try credentialIdToCredential.values.forEach { credential in
       switch credential.format {
       case .ldp_vc:
           guard let credentialData = credential.data.value as? [String:Any] else {
               throw InvalidData(message: "Credential data is not in the expected format", className: className)
           }
           let credentialSubjectId: String? = (credentialData["credentialSubject"] as? [String:Any] ?? [:])["id"] as? String
           credentialIdToTags[credential.credentialId] = W3cTaggedCredential(
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
           
           credentialIdToTags[credential.credentialId] = MdocTaggedCredential(
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
           
           credentialIdToTags[credential.credentialId] = SdJwtTaggedCredential(
               credentialFormat: credential.format,
               hasCryptographicHolderBinding: true,
               vct: sdJWTPayload["vct"] as? String ?? ""
           )
       }
   }
    
    return credentialIdToTags
}

func convertToProcessedCredentials(_ filteredWalletCredentialIds: [String], _ credentialIdToCredential: [String: Credential]) throws -> [any ProcessedCredential] {
    var processedCredentials: [any ProcessedCredential] = []
    
    for credentialId in filteredWalletCredentialIds {
        guard let credential = credentialIdToCredential[credentialId] else { continue }
        
        switch credential.format {
        case .ldp_vc:
            guard let credentialData = credential.data.value as? [String:Any] else {
                throw InvalidData(message: "Credential data is not in the expected format", className: className)
            }
            let claims = credentialData["credentialSubject"] as? [String:Any] ?? [:]
            
            processedCredentials.append(W3cCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: claims,
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
            
            processedCredentials.append(MdocCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                namespaces: namespaces,
            ))
            
        case .dc_sd_jwt, .vc_sd_jwt:
            guard let sdJwtCredential = credential.data.value as? String else {
                throw InvalidData(message: "SD-JWT credential is not a String", className: className)
            }
            
            let sdJWT = sdJwtCredential.split(separator: "~")[0]
            let sdJWTPayload = try JWSHandler.extractDataJsonFromJws(jws: String(sdJWT), jwsPart: .payload)
            
            let claims = sdJWTPayload["credentialSubject"] as? [String: Any] ?? sdJWTPayload
            
            processedCredentials.append(SdJwtCredential(
                credentialId: credential.credentialId,
                credentialFormat: credential.format,
                claims: claims,
            ))
        }
    }
    
    return processedCredentials
}

private func unwrapCbor(_ cbor: SwiftCBOR.CBOR) -> Any? {
    switch cbor {
    case let .utf8String(s): return s
    case let .boolean(b): return b
    case let .unsignedInt(u): return Int(u)
    case let .negativeInt(n): return -Int(n) - 1
    case let .double(d): return d
    case let .float(f): return f
    case let .half(h): return h
    case let .map(m):
        var dict: [String: Any] = [:]
        for (k, v) in m {
            if let strK = unwrapCbor(k) as? String {
                dict[strK] = unwrapCbor(v)
            }
        }
        return dict
    case let .array(a):
        return a.compactMap { unwrapCbor($0) }
    default:
        return nil
    }
}
