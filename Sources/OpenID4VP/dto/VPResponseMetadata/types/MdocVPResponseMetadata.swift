public struct MdocVPResponseMetadata : VPResponseMetadata {
    //map of docType to the signed deviceAuthenticationBytes
    let deviceAuthenticationBytesSigned : [String : String]
    static let className = String(describing: MdocVPResponseMetadata.self)
   
    func validate() throws {
        for (_, value) in deviceAuthenticationBytesSigned {
            if value.isEmpty || value == "null" {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["vp response metadata",value], className: MdocVPResponseMetadata.className)
            }
        }
    }
}
