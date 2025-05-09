struct UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    private let verifiableCredential: [String]
    private let id: String
    private let holder: String
    
    init( verifiableCredential: [String],
          id: String,
          holder: String) {
        self.verifiableCredential = verifiableCredential
        self.id = id
        self.holder = holder
    }
    
    func build() throws -> UnsignedVPToken {
        //parse the verifiableCredential array
        //get the @context property from each verifiableCredential
        //and add it to the context array
        return UnsignedLdpVPToken(context : ["https://www.w3.org/2018/credentials/v1"],
                                  type : ["VerifiablePresentation"],
                                  verifiableCredential: self.verifiableCredential,
                                  id: self.id,
                                  holder: self.holder)
    }
}
