public struct MdocVPResponseMetadata : VPResponseMetadata {
    //map of docType to the signed deviceAuthenticationBytes
    let deviceAuthenticationBytesSigned : [String : DeviceAuthentication]
    static let className = String(describing: MdocVPResponseMetadata.self)
   
    func validate() throws {
        for (_, value) in deviceAuthenticationBytesSigned {
            if value.signature.isEmpty || value.signature == "null" {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["vp response metadata->deviceAuthenticationBytesSigned",value.signature], className: MdocVPResponseMetadata.className)
            }
            if value.algorithm.isEmpty || value.algorithm == "null" {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["vp response metadata->signingAlgorithm",value.algorithm], className: MdocVPResponseMetadata.className)
            }
        }
    }
}

struct DeviceAuthentication {
    let signature: String
    let algorithm: String
}
