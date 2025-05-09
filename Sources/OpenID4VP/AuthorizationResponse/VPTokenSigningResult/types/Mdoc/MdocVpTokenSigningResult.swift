public struct MdocVPTokenSigningResult : VPTokenSigningResult {
    //map of docType to the signed deviceAuthenticationBytes
    let deviceAuthenticationBytesSigned : [String : DeviceAuthentication]
    static let className = String(describing: MdocVPTokenSigningResult.self)
    
    public init(deviceAuthenticationBytesSigned: [String: DeviceAuthentication]) {
        self.deviceAuthenticationBytesSigned = deviceAuthenticationBytesSigned
    }
    
    func validate() throws {
        if(deviceAuthenticationBytesSigned.isEmpty) {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["MdocVPTokenSigningResult","deviceAuthenticationBytesSigned"], className: MdocVPTokenSigningResult.className)
        }
        for (_, deviceAuthentication) in deviceAuthenticationBytesSigned {
            try deviceAuthentication.validate()
        }
    }
}
