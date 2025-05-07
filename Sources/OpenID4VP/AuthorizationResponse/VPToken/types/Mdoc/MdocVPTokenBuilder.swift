import Foundation
import SwiftCBOR

class MdocVPTokenBuilder : VpTokenBuilder {
    private let mdocVPResponeMetadata:  MdocVpTokenSigningResult
    private let unsignedMdocVPToken:  UnsignedMdocVPToken
    private let credentials: [String]
    private let className = String(describing: MdocVPTokenBuilder.self)
    
    init(mdocVPResponeMetadata:  MdocVpTokenSigningResult,unsignedMdocVPToken:  UnsignedMdocVPToken, credentials: [String]) {
        self.mdocVPResponeMetadata = mdocVPResponeMetadata
        self.unsignedMdocVPToken = unsignedMdocVPToken
        self.credentials = credentials
    }
    
    func build() throws -> VPToken {
        var documents : [CBOR] = []
        try mdocVPResponeMetadata.validate()
        
        try credentials.forEach { mdocCredential in
            guard var document = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw Logger.handleException(exceptionType: "InvalidData", message: "Invalid Verifiable Credential: Error while decoding credential", className: className)
            }
            guard let docType = getValueFromCBORMap(cborMap: document, key: "docType") else {
                throw Logger.handleException(exceptionType: "InvalidData", message: "Invalid Verifiable Credential: docType not available in credential", className: className)
            }
            let docTypeString = extractStringFromCBOR(docType)!
            
            guard let deviceAuthSignature: DeviceAuthentication = mdocVPResponeMetadata.deviceAuthenticationBytesSigned[docTypeString] else {
                throw Logger.handleException(exceptionType: "MissingInput",message: "Device authentication signature not found for mdoc credential docType \(docTypeString)", fieldPath: ["mdocVPResponeMetadata","deviceAuthenticationBytesSigned","DeviceAuthentication"], className: className)
            }
            
            let deviceSignature = try createDeviceSignature(deviceAuthSignature)
            
            let deviceAuth = CBOR.map([.utf8String("deviceSignature"): deviceSignature])
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
            .utf8String("status"): .unsignedInt(UInt64(0)), // Status = OK
        ])
        
        //base64 url encode without padding the deviceResponse
        let encodedDeviceResponseBase64Url = Data(cborEncode(deviceRespone)).toBase64UrlEncoded()
        return MdocVPToken(value: encodedDeviceResponseBase64Url)
    }
    
    // DeviceSignature is of COSE_Sign1 structure
    /**
     COSE_Sign1 = [
     Headers, //protected , unprotected in order
     payload : bstr / nil,
     signature : bstr
     ]
     */
    private func createDeviceSignature(_ vpResoonseMetadata: DeviceAuthentication) throws -> CBOR {
        let base64DecodedSignature = try Base64Decoder.decodeBase64ToData(vpResoonseMetadata.signature)
        let cborEncodedSignature = cborEncode(toCBOR(base64DecodedSignature))
        let protectedHeaders = CBOR.map([
            .unsignedInt(1): .negativeInt((try mapSigningAlgorithmToProtectedAlg(algorithm: vpResoonseMetadata.algorithm)))
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
