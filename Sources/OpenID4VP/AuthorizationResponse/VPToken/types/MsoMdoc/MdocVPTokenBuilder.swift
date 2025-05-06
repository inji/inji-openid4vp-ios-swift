import Foundation

class MdocVPTokenBuilder : VpTokenBuilder {
    private let mdocVPResponeMetadata:  MdocVPResponseMetadata
    private let unsignedMdocVPToken:  UnsignedMdocVPToken
    private let nonce: String
    private let authorizationRequest: AuthorizationRequest
    private let credentials: [String]
    
    init(mdocVPResponeMetadata:  MdocVPResponseMetadata,unsignedMdocVPToken:  UnsignedMdocVPToken, authorizationRequest: AuthorizationRequest, credentials: [String]) {
        self.mdocVPResponeMetadata = mdocVPResponeMetadata
        self.unsignedMdocVPToken = unsignedMdocVPToken
        self.nonce = authorizationRequest.nonce
        self.credentials = credentials
    }
    
    func build() throws -> VPToken {
        try mdocVPResponeMetadata.validate()
        // use vpResponseMetadata's devieAuthenticationBytesSigned to construct COSE_Sign1 structure
        // attach the constructed COSE_Sign1 structure to credential
        credentials.forEach { credential in
            guard let cborCredential = decodeCBOR(input: credential) else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1001, userInfo: nil)
            }
            guard let docType = getValueFromCBORMap(cborMap: cborCredential, key: "docType") else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1002, userInfo: nil)
            }
            guard let deviceAuthenticationBytes = unsignedMdocVPToken.deviceAuthenticationBytes[extractStringFromCBOR(docType)!] else {
                throw NSError(domain: "Invalid Verifiable Credential", code: 1003, userInfo: nil)
            }
            let coseSign1 = CoseSign1(
                payload: deviceAuthenticationBytes,
                detachPayload: true
            )
        }
        return MdocVPToken(value: "")
    }
}
