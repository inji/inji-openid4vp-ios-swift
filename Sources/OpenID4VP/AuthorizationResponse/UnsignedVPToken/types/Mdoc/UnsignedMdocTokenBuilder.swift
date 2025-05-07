import Foundation
import SwiftCBOR

struct UnsignedMdocVPTokenBuilder: UnsignedVPTokenBuilder {
    private let mdocCredentials: [String]
    private let clientId: String
    private let responseUri: String
    // nonce in Authorization Request parameter
    private let verifierNonce: String
    private let mdocGeneratedNonce: String
    static let className = String(describing: UnsignedMdocVPTokenBuilder.self)
    
    init( mdocCredentials: [String], clientId: String, responseUri: String, verifierNonce: String, mdocGeneratedNonce: String) {
        self.mdocCredentials = mdocCredentials
        self.clientId = clientId
        self.responseUri = responseUri
        self.verifierNonce = verifierNonce
        self.mdocGeneratedNonce = mdocGeneratedNonce
    }
    
    func build() throws ->  UnsignedVPToken {
        var deviceAuthenticationBytes : [String : String] = [:]
        let clientIdToHash = CBOR.array([.utf8String(clientId), .utf8String(self.mdocGeneratedNonce)])
        let clientIdHash = CBOR.byteString(SHA256Hash(from: clientIdToHash))
        let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(self.mdocGeneratedNonce)])
        let responseUriHash = CBOR.byteString(SHA256Hash(from: responseUriToHash))
        
        let openID4VPHandover = CBOR.array([clientIdHash, responseUriHash, .utf8String(self.mdocGeneratedNonce)])
        let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])
        
        let deviceNamespaces = CBOR.map([:])
        let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)
        
        for mdocCredential in self.mdocCredentials {
            guard let credential = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw Logger.handleException(exceptionType: "InvalidData", message: "Invalid Verifiable Credential: Error while decoding credential", className: UnsignedMdocVPTokenBuilder.className)
            }
            let docType: CBOR? = getValueFromCBORMap(cborMap: credential, key: "docType")
            
            let deviceAuthentication = CBOR.array([
                .utf8String("DeviceAuthentication"),
                sessionTranscript,
                docType!,
                deviceNamespacesBytes!
            ])
            
            let deviceAuthenticationBytesOfCredential = wrapCBORInputWithTag24(input: deviceAuthentication)
            deviceAuthenticationBytes[extractStringFromCBOR(docType!)!] = cborToByteString(cbor: deviceAuthenticationBytesOfCredential!)
        }
        
        return UnsignedMdocVPToken(deviceAuthenticationBytes: deviceAuthenticationBytes)
    }
}
