import Foundation
import SwiftCBOR

private let className = "CredentialUtils"

func expandCredentialTag(_ credential: Credential, jsonLdExpander: JsonLdExpanding) async throws -> TaggedCredential {
    switch credential.format {
    case .ldp_vc:
        guard let credentialData = credential.data.value as? [String:Any] else {
            throw InvalidData(message: "Credential data is not in the expected format", className: className)
        }
        let credentialSubjectId: String? = (credentialData["credentialSubject"] as? [String:Any] ?? [:])["id"] as? String
        let expandedCredential = try await jsonLdExpander.expand(data: credentialData)
        return W3cTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: credentialSubjectId != nil,
            types: expandedCredential["@type"] as? [String] ?? []
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
        let (_, sdJWTPayload) = try extractSdJwtPayload(credential.data, className: className)
        
        return SdJwtTaggedCredential(
            credentialFormat: credential.format,
            hasCryptographicHolderBinding: sdJWTPayload["cnf"] != nil,
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
            let (_, sdJWTPayload) = try extractSdJwtPayload(credential.data, className: className)
            
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
