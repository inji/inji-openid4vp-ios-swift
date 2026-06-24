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
        var documents: [CBOR] = []
        guard let payloadMap = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
            throw InvalidData(message: "Missing docTypeToDeviceAuthenticationBytes in payload", className: className)
        }

        var descriptorMaps: [DescriptorMap] = []

        for credentialInputDescriptorMapping in credentialInputDescriptorMappings {
            let document = try buildDocument(
                credential: credentialInputDescriptorMapping.credential,
                vpTokenSigningResults: vpTokenSigningResults,
                identifier: credentialInputDescriptorMapping.identifier,
                payloadMap: payloadMap
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

        let mdocVPToken = try buildMdocVPToken(documents: .array(documents))

        return ([mdocVPToken], descriptorMaps, rootIndex + 1)
    }
    
    func build(
        credentialToCredentialQueryIdMappings: [CredentialToCredentialQueryIdMapping],
        unsignedVPTokenResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]),
        vpTokenSigningResults: [VPTokenSigningResult]
    ) throws -> [String: [VPToken]] {
        guard let payloadMap = unsignedVPTokenResult.vpTokenSigningPayload as? [String: String] else {
            throw InvalidData(message: "Missing uuidToDeviceAuthenticationBytes in payload", className: className)
        }

        var vpTokenResult: [String: [VPToken]] = [:]

        for credentialToCredentialQueryIdMapping in credentialToCredentialQueryIdMappings {
            let document = try buildDocument(
                credential: credentialToCredentialQueryIdMapping.credential,
                vpTokenSigningResults: vpTokenSigningResults,
                identifier: credentialToCredentialQueryIdMapping.identifier,
                payloadMap: payloadMap
            )

            let mdocVPToken = try buildMdocVPToken(documents: .array([document]))
            vpTokenResult[credentialToCredentialQueryIdMapping.credentialQueryId, default: []].append(mdocVPToken)
        }

        return vpTokenResult
    }
    
    func buildDocument(
        credential: AnyCodable,
        vpTokenSigningResults: [VPTokenSigningResult],
        identifier: String?,
        payloadMap: [String: String]
    ) throws -> CBOR {
        guard let identifier = identifier else {
            throw InvalidData(message: "Missing identifier in credential mapping", className: className)
        }

        guard payloadMap[identifier] != nil else {
            throw InvalidData(message: "Missing payload for identifier: \(identifier)", className: className)
        }
        
        let vpTokenSigningResult = try getVPTokenSigningResult(
            vpTokenSigningResults: vpTokenSigningResults,
            identifier: identifier,
            className: className
        )
        
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
    
    private func buildMdocVPToken(documents: CBOR) throws -> MdocVPToken {
        let deviceResponse = CBOR.map([
            .utf8String("version"): .utf8String("1.0"),
            .utf8String("documents"): (documents),
            .utf8String("status"): .unsignedInt(UInt64(0)),
        ])
        let encodedDeviceResponseBase64Url = Data(cborEncode(deviceResponse)).toBase64UrlEncoded()
        return MdocVPToken(base64EncodedDeviceResponse: encodedDeviceResponseBase64Url)
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
