import Foundation
import CryptoKit
import JSONWebKey
import SwiftCBOR

struct UnsignedMdocVPTokenBuilder: UnsignedVPTokenBuilder {
    let authorizationRequest: AuthorizationRequest
    let specVersion: SpecVersion
    let walletMetadata: WalletMetadata?
    private let responseUri: String
    private let mdocGeneratedNonce: String
    
    static let className = String(describing: UnsignedMdocVPTokenBuilder.self)
    
    init(
        authorizationRequest: AuthorizationRequest,
        specVersion: SpecVersion,
        mdocGeneratedNonce: String,
        walletMetadata: WalletMetadata? = nil
    ) throws {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        self.walletMetadata = walletMetadata
        self.responseUri = try ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode).getResponseEndpoint(authorizationRequest: authorizationRequest)
        self.mdocGeneratedNonce = mdocGeneratedNonce
    }
    
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        var docTypeToDeviceAuthenticationBytes: [String: String] = [:]

        let openID4VPHandover = try SpecVersionHandler.from(specVersion).buildOpenID4VPHandover(
            authorizationRequest: authorizationRequest,
            mdocGeneratedNonce: mdocGeneratedNonce,
            responseUri: responseUri,
            walletMetadata: walletMetadata
        )
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])

        let deviceNamespaces = CBOR.map([:])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)!

        var unsignedVPTokens: [UnsignedVPToken] = []

        for index in 0..<credentialInputDescriptorMappings.count {
            let credentialInputDescriptorMapping = credentialInputDescriptorMappings[index]
            guard let mdocCredential = credentialInputDescriptorMapping.credential.value as? String else {
                throw InvalidData(
                    message: "MDOC credential is not a String",
                    className: AuthorizationResponseHandler.className
                )
            }
            guard let credential = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw InvalidData(
                    message: "Invalid Verifiable Credential: Error while decoding credential",
                    className: Self.className
                )
            }

            guard let docType = getValueFromCBORMap(cborMap: credential, key: "docType"),
                  let docTypeString = extractStringFromCBOR(docType) else {
                throw InvalidData(
                    message: "docType missing or invalid in credential",
                    className: Self.className
                )
            }

            if docTypeToDeviceAuthenticationBytes[docTypeString] != nil {
                throw InvalidData(
                    message: "Duplicate Mdoc Credentials with same doctype found",
                    className: Self.className
                )
            }

            let deviceAuthentication = CBOR.array([
                .utf8String("DeviceAuthentication"),
                sessionTranscript,
                docType,
                deviceNamespacesBytes
            ])

            let wrapped = wrapCBORInputWithTag24(input: deviceAuthentication)!
            let dataToSign = cborToByteString(cbor: wrapped)
            docTypeToDeviceAuthenticationBytes[docTypeString] = dataToSign
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: credentialInputDescriptorMapping.format,
                credential: credentialInputDescriptorMapping.credential,
                inputDescriptorId: credentialInputDescriptorMapping.inputDescriptorId,
                identifier: docTypeString
                )
            
            let (keyRef, alg) = try resolveMdocKeyAndAlg(mdocCredential)
            
            unsignedVPTokens.append(UnsignedVPToken(
                format: .mso_mdoc,
                holderKeyReference: keyRef,
                signatureAlgorithm: alg,
                dataToSign: dataToSign
            ))
        }


        unsignedVPTokens = []
        for docType in docTypeToDeviceAuthenticationBytes.keys.sorted() {
             let mapping = credentialInputDescriptorMappings.first(where: { $0.identifier == docType })!
             let mdocCredential = mapping.credential.value as! String
             let (keyRef, alg) = try resolveMdocKeyAndAlg(mdocCredential)
             unsignedVPTokens.append(UnsignedVPToken(
                format: .mso_mdoc,
                holderKeyReference: keyRef,
                signatureAlgorithm: alg,
                dataToSign: docTypeToDeviceAuthenticationBytes[docType]!
             ))
        }

        return (
            vpTokenSigningPayload: docTypeToDeviceAuthenticationBytes,
            unsignedVPTokens: unsignedVPTokens
        )
    }
    
    func build(credentialToCredentialQueryIdMappings: inout [CredentialToCredentialQueryIdMapping]) async throws -> (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) {
        var docTypeToDeviceAuthenticationBytes: [String: String] = [:]

        let openID4VPHandover = try SpecVersionHandler.from(specVersion).buildOpenID4VPHandover(
            authorizationRequest: authorizationRequest,
            mdocGeneratedNonce: mdocGeneratedNonce,
            responseUri: responseUri,
            walletMetadata: walletMetadata
        )
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])

        let deviceNamespaces = CBOR.map([:])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)!

        var unsignedVPTokens: [UnsignedVPToken] = []

        for index in 0..<credentialToCredentialQueryIdMappings.count {
            let credentialInputDescriptorMapping = credentialToCredentialQueryIdMappings[index]
            guard let mdocCredential = credentialInputDescriptorMapping.credential.value as? String else {
                throw InvalidData(
                    message: "MDOC credential is not a String",
                    className: AuthorizationResponseHandler.className
                )
            }
            guard let credential = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw InvalidData(
                    message: "Invalid Verifiable Credential: Error while decoding credential",
                    className: Self.className
                )
            }

            guard let docType = getValueFromCBORMap(cborMap: credential, key: "docType"),
                  let docTypeString = extractStringFromCBOR(docType) else {
                throw InvalidData(
                    message: "docType missing or invalid in credential",
                    className: Self.className
                )
            }

            if docTypeToDeviceAuthenticationBytes[docTypeString] != nil {
                throw InvalidData(
                    message: "Duplicate Mdoc Credentials with same doctype found",
                    className: Self.className
                )
            }

            let deviceAuthentication = CBOR.array([
                .utf8String("DeviceAuthentication"),
                sessionTranscript,
                docType,
                deviceNamespacesBytes
            ])

            let wrapped = wrapCBORInputWithTag24(input: deviceAuthentication)!
            let dataToSign = cborToByteString(cbor: wrapped)
            docTypeToDeviceAuthenticationBytes[docTypeString] = dataToSign
            
            let (keyRef, alg) = try resolveMdocKeyAndAlg(mdocCredential)
            
            unsignedVPTokens.append(UnsignedVPToken(
                format: .mso_mdoc,
                holderKeyReference: keyRef,
                signatureAlgorithm: alg,
                dataToSign: dataToSign
            ))
        }


        unsignedVPTokens = []
        for docType in docTypeToDeviceAuthenticationBytes.keys.sorted() {
             let mapping = credentialToCredentialQueryIdMappings.first(where: { $0.identifier == docType })!
             let mdocCredential = mapping.credential.value as! String
             let (keyRef, alg) = try resolveMdocKeyAndAlg(mdocCredential)
             unsignedVPTokens.append(UnsignedVPToken(
                format: .mso_mdoc,
                holderKeyReference: keyRef,
                signatureAlgorithm: alg,
                dataToSign: docTypeToDeviceAuthenticationBytes[docType]!
             ))
        }

        return (
            vpTokenSigningPayload: docTypeToDeviceAuthenticationBytes,
            unsignedVPTokens: unsignedVPTokens
        )
    }
    
    private enum SpecVersionHandler {
        case specV1, draft23
        
        static func from(_ specVersion: SpecVersion) -> SpecVersionHandler {
            return specVersion == .v1 ? .specV1 : .draft23
        }
        
        func buildOpenID4VPHandover(authorizationRequest: AuthorizationRequest, mdocGeneratedNonce: String, responseUri: String, walletMetadata: WalletMetadata?) throws -> CBOR {
            switch self {
            case .draft23:
                let clientIdToHash = CBOR.array([.utf8String(authorizationRequest.clientId), .utf8String(mdocGeneratedNonce)])
                let clientIdHash = CBOR.byteString(sha256Hash(from: clientIdToHash))

                let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(mdocGeneratedNonce)])
                let responseUriHash = CBOR.byteString(sha256Hash(from: responseUriToHash))
                return CBOR.array([clientIdHash, responseUriHash, .utf8String(authorizationRequest.nonce)])
            case .specV1:
                let responseHandler = try ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode)
                let verifierPublicKey = try responseHandler.getVerifierPublicKeyForEncryption(
                    authorizationRequest: authorizationRequest,
                    walletMetadata: walletMetadata
                )
                
                let thumbprintCBOR: CBOR = try verifierPublicKey?.toJWKThumbprintBstr() ?? .null
                
                let openId4VPHandoverInfo = CBOR.array([
                    .utf8String(authorizationRequest.clientId),
                    .utf8String(authorizationRequest.nonce),
                    thumbprintCBOR,
                    .utf8String(responseUri)
                ])
                let openId4VPHandoverInfoBytes: [UInt8] = openId4VPHandoverInfo.encode()
                let handoverInfoHash = CBOR.byteString([UInt8](Data(SHA256.hash(data: Data(openId4VPHandoverInfoBytes)))))
                return CBOR.array([.utf8String("OpenID4VPHandover"), handoverInfoHash])
            }
        }
    }
}

