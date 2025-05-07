public struct MdocVPResponseMetadata : VPResponseMetadata {
    //map of docType to the signed deviceAuthenticationBytes
    let deviceAuthenticationBytesSigned : [String : DeviceAuthentication]
    static let className = String(describing: MdocVPResponseMetadata.self)
    
    func validate() throws {
        for (_, deviceAuthentication) in deviceAuthenticationBytesSigned {
            try deviceAuthentication.validate()
        }
    }
}
