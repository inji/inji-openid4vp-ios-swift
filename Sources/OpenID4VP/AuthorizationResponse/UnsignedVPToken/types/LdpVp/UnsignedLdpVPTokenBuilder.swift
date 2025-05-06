struct UnsignedLdpVPTokenBuilder: UnsignedVPTokenBuilder {
    let verifiableCredential: [String]
    let id: String
    let holder: String

//TODO: Format the file
    init( verifiableCredential: [String],
     id: String,
     holder: String) {
        self.verifiableCredential = verifiableCredential
        self.id = id
        self.holder = holder
     }

     func build() throws -> UnsignedVPToken {
        return UnsignedLdpVPToken(context : ["https://www.w3.org/2018/credentials/v1"]
    type : ["VerifiablePresentation"]
    verifiableCredential: self.verifiableCredential
    id: self.id
    holder: self.holder)
     }
}