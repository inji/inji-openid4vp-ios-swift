import Foundation
import SwiftCBOR

class MdocVPTokenBuilder : VPTokenBuilder {
    private let className = String(describing: MdocVPTokenBuilder.self)
    
    let authorizationRequest: AuthorizationRequest
    
    init(authorizationRequest: AuthorizationRequest) {
        self.authorizationRequest = authorizationRequest
    }
    
    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult],
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        var documents : [CBOR] = []
        guard let docTypeToDeviceAuthenticationBytes = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
            throw InvalidData(message: "Missing docTypeToDeviceAuthenticationBytes in payload", className: className)
        }
        
        var descriptorMaps : [DescriptorMap] = []
        var signingResultsIterator = vpTokenSigningResults.makeIterator()
        
        // Process docTypes in the same deterministic sorted order used when unsigned tokens are flattened.
        for docTypeString in docTypeToDeviceAuthenticationBytes.keys.sorted() {
            guard let vpTokenSigningResult = signingResultsIterator.next() else {
                throw InvalidData(message: "Missing signing result for \(docTypeString)", className: className)
            }
            
            guard let credentialInputDescriptorMapping = credentialInputDescriptorMappings.first(where: { $0.identifier == docTypeString }) else {
                throw InvalidData(message: "Missing mapping for \(docTypeString)", className: className)
            }
            
            let document = try buildDocument(
                credential: credentialInputDescriptorMapping.credential,
                vpTokenSigningResult: vpTokenSigningResult
            )
            
            documents.append(document)
            descriptorMaps.append(
                DescriptorMap(
                    id: credentialInputDescriptorMapping.inputDescriptorId,
                    format: .mso_mdoc,
                    path: createDescriptorMapPath(rootIndex),
                    pathNested: createNestedPath(
                        id: credentialInputDescriptorMapping.inputDescriptorId,
                        nestedPath: credentialInputDescriptorMapping.nestedPath,
                        format: .mso_mdoc
                    )
                )
            )
        }
        
        if signingResultsIterator.next() != nil {
            throw InvalidData(message: "Extra signing results provided for mso_mdoc", className: className)
        }
        
        let deviceResponse = CBOR.map([
            .utf8String("version"): .utf8String("1.0"),
            .utf8String("documents"): .array(documents),
            .utf8String("status"): .unsignedInt(UInt64(0)), // Status = OK
        ])
        
        //base64 url encode without padding the deviceResponse
        let encodedDeviceResponseBase64Url = Data(cborEncode(deviceResponse)).toBase64UrlEncoded()
        let mdocVPToken = MdocVPToken(base64EncodedDeviceResponse: encodedDeviceResponseBase64Url)
        
        return ([mdocVPToken], descriptorMaps, rootIndex + 1)
    }
    
    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        var queryIdToDocumentsMap : [String: [CBOR]] = [:]
        guard let docTypeToDeviceAuthenticationBytes = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
            throw InvalidData(message: "Missing docTypeToDeviceAuthenticationBytes in payload", className: className)
        }
        
        var signingResultsIterator = vpTokenSigningResults.makeIterator()
        var vpTokenResult : [String: [VPToken]] = [:]
        
        // Process docTypes in the same deterministic sorted order used when unsigned tokens are flattened.
        for docTypeString in docTypeToDeviceAuthenticationBytes.keys.sorted() {
            guard let vpTokenSigningResult = signingResultsIterator.next() else {
                throw InvalidData(message: "Missing signing result for \(docTypeString)", className: className)
            }
            
            guard let credentialToCredentialQueryIdMapping = credentialToCredentialQueryIdMappings.first(where: { $0.identifier == docTypeString }) else {
                throw InvalidData(message: "Missing mapping for \(docTypeString)", className: className)
            }
            
            let document = try buildDocument(
                credential: credentialToCredentialQueryIdMapping.credential,
                vpTokenSigningResult: vpTokenSigningResult
            )
            
            queryIdToDocumentsMap[credentialToCredentialQueryIdMapping.credentialQueryId, default: []]
                .append(document)
        }
        
        if signingResultsIterator.next() != nil {
            throw InvalidData(message: "Extra signing results provided for mso_mdoc", className: className)
        }
        
        for (queryId, documents) in queryIdToDocumentsMap {
            let deviceResponse = CBOR.map([
                .utf8String("version"): .utf8String("1.0"),
                .utf8String("documents"): .array(documents),
                .utf8String("status"): .unsignedInt(UInt64(0)), // Status = OK
            ])
            //base64 url encode without padding the deviceResponse
            let encodedDeviceResponseBase64Url = Data(cborEncode(deviceResponse)).toBase64UrlEncoded()
            let mdocVPToken = MdocVPToken(base64EncodedDeviceResponse: encodedDeviceResponseBase64Url)
            
            vpTokenResult[queryId] = [mdocVPToken]
        }
        
        return vpTokenResult
    }
    
    func buildDocument(
        credential: AnyCodable,
        vpTokenSigningResult: VPTokenSigningResult
    ) throws -> CBOR {
        guard let mdocCredential = credential.value as? String else {
            throw InvalidType(
                message: "Invalid MSO-MDOC token: expected String",
                className: className
            )
        }
        guard var document = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
            throw InvalidData( message: "Invalid Verifiable Credential: Error while decoding credential", className: className)
        }
        
        let (_, alg) = try resolveMdocKeyAndAlg(mdocCredential)
        
        let deviceAuthSignature = DeviceAuthentication(signature: vpTokenSigningResult.signedData, algorithm: alg)
        
        let deviceSignature = try createDeviceSignature(deviceAuthSignature)
        
        let deviceAuth = CBOR.map([.utf8String("deviceSignature"): deviceSignature])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: CBOR.map([:]))!
        let deviceSigned = CBOR.map([
            .utf8String("deviceAuthentication"): deviceAuth,
            .utf8String("namespaces"): deviceNamespacesBytes,
        ])
        
        // attach deviceSigned to cborCredential
        document[CBOR.utf8String("deviceSigned")] = deviceSigned
        
        return document
    }
    
    // DeviceSignature is of COSE_Sign1 structure
    /**
     COSE_Sign1 = [
     Headers, //protected , unprotected in order
     payload : bstr / nil,
     signature : bstr
     ]
     */
    private func createDeviceSignature(_ vpResponseMetadata: DeviceAuthentication) throws -> CBOR {
        let base64DecodedSignature = vpResponseMetadata.signature
        let cborEncodedSignature = cborEncode(toCBOR(base64DecodedSignature))
        let protectedHeaders = CBOR.map([
            .unsignedInt(1): try mapSigningAlgorithmToProtectedAlg(algorithm: vpResponseMetadata.algorithm)
        ])
        let unprotectedHeaders = CBOR.map([:])
        //Payload is available as detached content
        let payload = CBOR.null
        
        return CBOR.array([
            .byteString(cborEncode(protectedHeaders)),
            unprotectedHeaders,
            payload,
            .byteString(cborEncodedSignature),
        ])
    }
}
