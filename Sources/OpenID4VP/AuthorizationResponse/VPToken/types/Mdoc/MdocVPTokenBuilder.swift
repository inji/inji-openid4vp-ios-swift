import Foundation
import SwiftCBOR

class MdocVPTokenBuilder : VpTokenBuilder {
    private let mdocVPResponeMetadata:  MdocVPResponseMetadata
    private let unsignedMdocVPToken:  UnsignedMdocVPToken
    private let nonce: String
    private let credentials: [String]
    
    init(mdocVPResponeMetadata:  MdocVPResponseMetadata,unsignedMdocVPToken:  UnsignedMdocVPToken, nonce: String, credentials: [String]) {
        self.mdocVPResponeMetadata = mdocVPResponeMetadata
        self.unsignedMdocVPToken = unsignedMdocVPToken
        self.nonce = nonce
        self.credentials = credentials
    }
    
    func build() throws -> VPToken {
        var documents : [CBOR] = []
        try mdocVPResponeMetadata.validate()
        
        try credentials.forEach { mdocCredential in
            guard var document = decodeCBOR(input: mdocCredential) else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1001, userInfo: nil)
            }
            guard let docType = getValueFromCBORMap(cborMap: document, key: "docType") else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1002, userInfo: nil)
            }
            let docTypeString = extractStringFromCBOR(docType)!
            guard unsignedMdocVPToken.deviceAuthenticationBytes[docTypeString] != nil else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1003, userInfo: nil)
            }
            
            //TODO: throw error if credential's docType is not available in VPResponseMetadata

            // create COSE_Sign1 structure
            let vpResoonseMetadata: DeviceAuthentication = mdocVPResponeMetadata.deviceAuthenticationBytesSigned[docTypeString]!
            let coseSign1 = CBOR.array([
                //TODO: algorithm value need to be following the COSE spec 1 -> -7
                .map([.utf8String("alg"): .utf8String(vpResoonseMetadata.algorithm)]),
                .null,
                .null,
                //TODO: Base64 Decode the signature before adding
                .utf8String(vpResoonseMetadata.signature)
            ])
            
            
            let deviceAuth = CBOR.map([.utf8String("deviceSignature"): coseSign1])
            let deviceNamespacesBytes = wrapCBORInputWithTag24(input: CBOR.map([:]))!
            let deviceSigned = CBOR.map([
                .utf8String("deviceAuthentication"): deviceAuth,
                .utf8String("namespaces"): deviceNamespacesBytes,
            ])
            
            // attach deviceSigned to cborCredential
            document[CBOR.utf8String("deviceSigned")] = deviceSigned
            
            documents.append(document)
        }
        let deviceRespone = CBOR.map([
            .utf8String("version"): .utf8String("1.0"),
            .utf8String("documents"): .array(documents),
            .utf8String("status"): .unsignedInt(UInt64(0)),
        ])
       
        //base64 url encode without padding the deviceResponse
        let encodedDeviceResponseBase64Url = Data(cborEncode(deviceRespone)!).toBase64UrlEncoded()
        return MdocVPToken(value: encodedDeviceResponseBase64Url)
    }
}
