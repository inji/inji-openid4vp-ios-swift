public struct MdocVpTokenSigningResult : VpTokenSigningResult {
    //map of docType to the signed deviceAuthenticationBytes
    let deviceAuthenticationBytesSigned : [String : DeviceAuthentication]
    static let className = String(describing: MdocVpTokenSigningResult.self)
    
    public init(deviceAuthenticationBytesSigned: [String: DeviceAuthentication]) {
        self.deviceAuthenticationBytesSigned = deviceAuthenticationBytesSigned
    }
    
    func validate() throws {
        if(deviceAuthenticationBytesSigned.isEmpty) {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["MdocVpTokenSigningResult","deviceAuthenticationBytesSigned"], className: MdocVpTokenSigningResult.className)
        }
        for (_, deviceAuthentication) in deviceAuthenticationBytesSigned {
            try deviceAuthentication.validate()
        }
    }
}
