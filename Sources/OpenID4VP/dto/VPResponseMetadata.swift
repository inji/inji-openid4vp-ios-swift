public struct VPResponseMetadata {
    let jws: String
    let signatureAlgorithm: String
    let publicKey: String
    let domain: String
    static let className = String(describing: VPResponseMetadata.self)
    
    public init(jws: String, signatureAlgorithm: String, publicKey: String, domain: String) {
        self.jws = jws
        self.signatureAlgorithm = signatureAlgorithm
        self.publicKey = publicKey
        self.domain = domain
    }
    
    func validate() throws {
        let requiredParams: [String: String] = [
            "jws": jws,
            "signatureAlgorithm": signatureAlgorithm,
            "publicKey": publicKey,
            "domain": domain
        ]
        
        for (_, value) in requiredParams {
            if value.isEmpty || value == "null" {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["vp response metadata",value], className: VPResponseMetadata.className)
            }
        }
    }
}
