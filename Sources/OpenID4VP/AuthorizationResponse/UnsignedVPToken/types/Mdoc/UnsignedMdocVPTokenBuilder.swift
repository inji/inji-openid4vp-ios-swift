import Foundation
import CryptoKit
import JSONWebKey
import SwiftCBOR

struct UnsignedMdocVPTokenBuilder: UnsignedVPTokenBuilder {
    let authorizationRequest: AuthorizationRequestV2
    let specVersion: SpecVersion
    private let responseUri: String
    private let mdocGeneratedNonce: String
    
    private let versionLogic: VersionLogic
    
    static let className = String(describing: UnsignedMdocVPTokenBuilder.self)

    init(
        authorizationRequest: AuthorizationRequestV2,
        specVersion: SpecVersion,
        responseUri: String,
        mdocGeneratedNonce: String
    ) {
        self.authorizationRequest = authorizationRequest
        self.specVersion = specVersion
        
        self.versionLogic = specVersion == .v1 ? .specV1 : .draft23
        
        self.responseUri = responseUri
        self.mdocGeneratedNonce = mdocGeneratedNonce
    }
    
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) async throws -> (vpTokenSigningPayload: VPTokenSigningPayload?, unsignedVPToken: UnsignedVPToken) {
        var docTypeToDeviceAuthenticationBytes: [String: String] = [:]

        let openID4VPHandover = try versionLogic.buildOpenID4VPHandover(authorizationRequest: authorizationRequest, mdocGeneratedNonce: mdocGeneratedNonce, responseUri: responseUri)
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])

        let deviceNamespaces = CBOR.map([:])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)!

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
            docTypeToDeviceAuthenticationBytes[docTypeString] = cborToByteString(cbor: wrapped)
            credentialInputDescriptorMappings[index] = CredentialInputDescriptorMapping(
                format: credentialInputDescriptorMapping.format,
                credential: credentialInputDescriptorMapping.credential,
                inputDescriptorId: credentialInputDescriptorMapping.inputDescriptorId,
                identifier: docTypeString
                )
        }

        let unsignedMdocVPToken = UnsignedMdocVPToken(docTypeToDeviceAuthenticationBytes: docTypeToDeviceAuthenticationBytes)

        return (
            vpTokenSigningPayload: nil,
            unsignedVPToken: unsignedMdocVPToken
        )
    }
    
    private enum VersionLogic {
        case specV1, draft23
        
        func buildOpenID4VPHandover(authorizationRequest: AuthorizationRequestV2, mdocGeneratedNonce: String, responseUri: String) throws -> CBOR {
            switch self {
            case .draft23:
                let clientIdToHash = CBOR.array([.utf8String(authorizationRequest.clientId), .utf8String(mdocGeneratedNonce)])
                let clientIdHash = CBOR.byteString(sha256Hash(from: clientIdToHash))

                let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(mdocGeneratedNonce)])
                let responseUriHash = CBOR.byteString(sha256Hash(from: responseUriToHash))
               return CBOR.array([clientIdHash, responseUriHash, .utf8String(authorizationRequest.nonce)])
            case .specV1:
                let clientMetadata = (authorizationRequest as? AuthorizationRequestSpecVersion1)?.clientMetadata
                let verifierPublicKey: JWK = try getEncryptionKey((clientMetadata?.jwks!)!, (clientMetadata?.authorizationEncryptedResponseAlg!)!)
                let jwkThumbprintBase64url = try verifierPublicKey.thumbprint(with: SHA256())
                guard let jwkThumbprintData = Data(base64Encoded: jwkThumbprintBase64url.base64URLToBase64()) else {
                    throw InvalidData(message: "Failed to decode JWK thumbprint bytes", className: UnsignedMdocVPTokenBuilder.className)
                }
                let jwkThumbprintBstr = CBOR.byteString([UInt8](jwkThumbprintData))
                let openId4VPHandoverInfo = CBOR.array([
                    .utf8String(authorizationRequest.clientId),
                    .utf8String(authorizationRequest.nonce),
                    jwkThumbprintBstr,
                    .utf8String(responseUri)
                ])
                let openId4VPHandoverInfoBytes: [UInt8] = openId4VPHandoverInfo.encode()
                let handoverInfoHash = CBOR.byteString([UInt8](Data(SHA256.hash(data: Data(openId4VPHandoverInfoBytes)))))
                
                return CBOR.array([.utf8String("OpenID4VPHandover"), handoverInfoHash])
            }
        }
    }
}
