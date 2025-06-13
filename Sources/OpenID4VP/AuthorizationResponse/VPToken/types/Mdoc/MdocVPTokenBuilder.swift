import Foundation
import SwiftCBOR

class MdocVPTokenBuilder : VPTokenBuilder {
    private let mdocVPTokenSigningResult:  MdocVPTokenSigningResult
    private let credentials: [String]
    private let className = String(describing: MdocVPTokenBuilder.self)
    
    init(mdocVPTokenSigningResult:  MdocVPTokenSigningResult, credentials: [String]) {
        self.mdocVPTokenSigningResult = mdocVPTokenSigningResult
        self.credentials = credentials
    }
    
    func build() throws -> VPToken {
        var documents : [CBOR] = []
        try mdocVPTokenSigningResult.validate()
        
        try credentials.forEach { mdocCredential in
            guard var document = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
                throw Logger.handleException(exceptionType: "InvalidData", message: "Invalid Verifiable Credential: Error while decoding credential", className: className)
            }
            guard let docType = getValueFromCBORMap(cborMap: document, key: "docType") else {
                throw Logger.handleException(exceptionType: "InvalidData", message: "Invalid Verifiable Credential: docType not available in credential", className: className)
            }
            let docTypeString = extractStringFromCBOR(docType)!
            
            guard let deviceAuthSignature: DeviceAuthentication = mdocVPTokenSigningResult.docTypeToDeviceAuthentication[docTypeString] else {
                throw Logger.handleException(exceptionType: "MissingInput",message: "Device authentication signature not found for mdoc credential docType \(docTypeString)", fieldPath: ["mdocVPTokenSigningResult","docTypeToDeviceAuthentication","DeviceAuthentication"], className: className)
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
        
        let deviceResponse = CBOR.map([
            .utf8String("version"): .utf8String("1.0"),
            .utf8String("documents"): .array(documents),
            .utf8String("status"): .unsignedInt(UInt64(0)), // Status = OK
        ])
        
        //base64 url encode without padding the deviceResponse
        let encodedDeviceResponseBase64Url = Data(cborEncode(deviceResponse)).toBase64UrlEncoded()
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
    private func createDeviceSignature(_ vpResponseMetadata: DeviceAuthentication) throws -> CBOR {
        let base64DecodedSignature = try Base64Decoder.decodeBase64ToData(vpResponseMetadata.signature)
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
