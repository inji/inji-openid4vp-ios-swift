struct UnsignedMdocVPTokenBuilder: UnsignedVPTokenBuilder {
    let verifiableCredential: [String]
    let clientId: String
    let responseUri: String
    let nonce: String

//TODO: Format the file
    init( verifiableCredentials: [String], clientId: String, responseUri: String, nonce: String) {
        self.verifiableCredential = verifiableCredential
        self.clientId = clientId
        self.responseUri = responseUri
        self.nonce = nonce
     }

     func build() throws -> UnsignedVPToken {
        return UnsignedLdpVPToken(context : ["https://www.w3.org/2018/credentials/v1"]
    type : ["VerifiablePresentation"]
    verifiableCredential: self.verifiableCredential
    id: self.id
    holder: self.holder)
     }

    func build() throws ->  UnsignedVPToken {
        //TODO: Accept this param as input
        let mdocGeneratedNonce = (createNonce())
        var deviceAuthenticationBytes : [String : String] = [:]
        for verifiableCredential in verifiableCredentials {
            guard let credential = decodeCBOR(input: verifiableCredential) else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1001, userInfo: nil)
            }
            
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
            
            let deviceAuthenticationBytesOfCredential = wrapCBORInputWithTag24(input: deviceAuthentication)
            deviceAuthenticationBytes[extractStringFromCBOR(docType!)!] = cborToByteString(cbor: deviceAuthenticationBytesOfCredential!)
        }

        return UnsignedMdocVPToken(deviceAuthenticationBytes: deviceAuthenticationBytes)
    }
}


//TODO: Move CBOR related functions to CBORUtils
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