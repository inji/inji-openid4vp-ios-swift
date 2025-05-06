import SwiftCBOR
import Foundation

public struct UnsignedMdocVPToken: Codable, UnsignedVPToken {
    // map of docType to map of signature algorithm and deviceAuthenticationBytes which will be used as payload for signing
    var deviceAuthenticationBytes : [String : String] = [:]
    
    init(verifiableCredentials: [String], clientId: String, responseUri: String, nonce: String) throws {
        for verifiableCredential in verifiableCredentials {
            guard let credential = decodeCBOR(input: verifiableCredential) else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1001, userInfo: nil)
            }
            
            
            let mdocGeneratedNonce = (createNonce())
            let clientIdToHash = CBOR.array([.utf8String(clientId), .utf8String(mdocGeneratedNonce)])
            let clientIdHash = CBOR.byteString(SHA256Hash(from: clientIdToHash))
            let responseUriToHash = CBOR.array([.utf8String(responseUri), .utf8String(mdocGeneratedNonce)])
            let responseUriHash = CBOR.byteString(SHA256Hash(from: responseUriToHash))
            
            let openID4VPHandover = CBOR.array([clientIdHash, responseUriHash, .utf8String(nonce)])
            let sessionTranscript = CBOR.array([.null, .null, openID4VPHandover])
            
            let docType: CBOR? = getValueFromCBORMap(cborMap: credential, key: "docType")
            
            let deviceNamespaces = CBOR.map([:])
            let deviceNamespacesBytes = wrapCBORInputWithTag24(input: deviceNamespaces)
            let deviceAuthentication = CBOR.array([
                .utf8String("DeviceAuthentication"),
                sessionTranscript,
                docType!,
                deviceNamespacesBytes!
            ])
            
            let deviceAuthenticationBytes = wrapCBORInputWithTag24(input: deviceAuthentication)
            self.deviceAuthenticationBytes[extractStringFromCBOR(docType!)!] = cborToByteString(cbor: deviceAuthenticationBytes!)
        }
    }
    
    func print(){
        for (k, v) in deviceAuthenticationBytes {
            Swift.print("\(k): \(v)")
        }
    }
}

func getValueFromCBORMap(cborMap: CBOR, key: String) -> CBOR? {
    guard case let .map(items) = cborMap else { return nil }
    
    let cborKey = CBOR.utf8String(key)
    return items[cborKey]
}

func extractStringFromCBOR(_ cbor: CBOR) -> String? {
    if case let .utf8String(str) = cbor {
        return str
    }
    return nil
}

func cborToByteString(cbor: CBOR) -> String {
    let encodedData : [UInt8] = CBOR.encode(cbor)
    
    return encodedData.map { String(format: "%02x", $0) }.joined()
}
