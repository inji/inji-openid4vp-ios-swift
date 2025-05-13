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
        //parse the verifiableCredential array
        //get the @context property's first entry from each verifiableCredential
        //and add it to the context
        var context = Set<String>()
        self.verifiableCredential.forEach { credential in
            if let contextValue = credential["@context"] as? [String] {
                context.insert(contextValue[0])
            }
        }
        
        return UnsignedLdpVPToken(context : Array(context),
                                  type : ["VerifiablePresentation"],
                                  verifiableCredential: self.verifiableCredential.map { $0.mapValues { AnyCodable($0) } },
                                  id: self.id,
                                  holder: self.holder)
    }
}
