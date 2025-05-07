public struct MdocVPResponseMetadata : VPResponseMetadata {
    //map of docType to the signed deviceAuthenticationBytes
    let deviceAuthenticationBytesSigned : [String : DeviceAuthentication]
    static let className = String(describing: MdocVPResponseMetadata.self)
    
    public init(deviceAuthenticationBytesSigned: [String: DeviceAuthentication]) {
        self.deviceAuthenticationBytesSigned = deviceAuthenticationBytesSigned
    }
    
    func validate() throws {
        if(deviceAuthenticationBytesSigned.isEmpty) {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["MdocVPResponseMetadata","deviceAuthenticationBytesSigned"], className: MdocVPResponseMetadata.className)
        }
        for (_, deviceAuthentication) in deviceAuthenticationBytesSigned {
            try deviceAuthentication.validate()
        }
    }
}
