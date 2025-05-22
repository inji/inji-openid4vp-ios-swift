struct UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let verifiableCredential: [[String: Any]]
    private let id: String
    private let holder: String
    
    init( verifiableCredential: [[String: Any]],
          id: String,
          holder: String) {
        self.verifiableCredential = verifiableCredential
        self.id = id
        self.holder = holder
    }
    
    func build() throws -> UnsignedVPToken {
        let context = ["https://www.w3.org/2018/credentials/v1"]
        return UnsignedLdpVPToken(context : context,
                                  type : ["VerifiablePresentation"],
                                  verifiableCredential: self.verifiableCredential.map { $0.mapValues { AnyCodable($0) } },
                                  id: self.id,
                                  holder: self.holder)
    }
}
