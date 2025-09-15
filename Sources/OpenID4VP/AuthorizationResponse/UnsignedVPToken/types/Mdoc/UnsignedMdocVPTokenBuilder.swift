import Foundation
import SwiftCBOR

struct UnsignedMdocVPTokenBuilder: UnsignedVPTokenBuilder {
    private let mdocCredentials: [String]
    private let clientId: String
    private let responseUri: String
    private let verifierNonce: String
    private let mdocGeneratedNonce: String
    static let className = String(describing: UnsignedMdocVPTokenBuilder.self)

    init(
        mdocCredentials: [String],
        clientId: String,
        responseUri: String,
        verifierNonce: String,
        mdocGeneratedNonce: String
    ) {
        self.mdocCredentials = mdocCredentials
        self.clientId = clientId
        self.responseUri = responseUri
        self.verifierNonce = verifierNonce
        self.mdocGeneratedNonce = mdocGeneratedNonce
    }

    func build() throws -> [String: Any] {
        var docTypeToDeviceAuthenticationBytes: [String: String] = [:]

        let clientIdToHash = CBOR.array([.utf8String(clientId), .utf8String(mdocGeneratedNonce)])
        let clientIdHash = CBOR.byteString(sha256Hash(from: clientIdToHash))

        let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(mdocGeneratedNonce)])
        let responseUriHash = CBOR.byteString(sha256Hash(from: responseUriToHash))

        let openID4VPHandover = CBOR.array([clientIdHash, responseUriHash, .utf8String(verifierNonce)])
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])

        let deviceNamespaces = CBOR.map([:])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)!

        for mdocCredential in mdocCredentials {
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
        }

        let unsignedMdocVPToken = UnsignedMdocVPToken(docTypeToDeviceAuthenticationBytes: docTypeToDeviceAuthenticationBytes) // ✅ Use the model

        return [
            "unsignedVPToken": unsignedMdocVPToken,
            "vpTokenSigningPayload": mdocCredentials
        ]
    }
    
    
    func build(credentialInputDescriptorMappings: inout [CredentialInputDescriptorMapping]) throws -> (payload: Any?, unsignedVPToken: UnsignedVPToken) {
        var docTypeToDeviceAuthenticationBytes: [String: String] = [:]

        let clientIdToHash = CBOR.array([.utf8String(clientId), .utf8String(mdocGeneratedNonce)])
        let clientIdHash = CBOR.byteString(sha256Hash(from: clientIdToHash))

        let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(mdocGeneratedNonce)])
        let responseUriHash = CBOR.byteString(sha256Hash(from: responseUriToHash))

        let openID4VPHandover = CBOR.array([clientIdHash, responseUriHash, .utf8String(verifierNonce)])
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])

        let deviceNamespaces = CBOR.map([:])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)!

        for credentialInputDescriptorMapping in credentialInputDescriptorMappings {
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
            credentialInputDescriptorMapping.identifier = docTypeString
        }

        let unsignedMdocVPToken = UnsignedMdocVPToken(docTypeToDeviceAuthenticationBytes: docTypeToDeviceAuthenticationBytes) 

        return (
            payload: nil,
            unsignedVPToken: unsignedMdocVPToken
        )
    }
}
