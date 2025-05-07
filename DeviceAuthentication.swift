struct DeviceAuthentication {
    let signature: String
    let algorithm: String
    
    func validate() throws {
        if self.signature.isEmpty || self.signature == "null" {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["vp response metadata->deviceAuthenticationBytesSigned",self.signature], className: MdocVPResponseMetadata.className)
        }
        if self.algorithm.isEmpty || self.algorithm == "null" {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["vp response metadata->signingAlgorithm",self.algorithm], className: MdocVPResponseMetadata.className)
        }
    }
    
}