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
            // @context property is an ordered set of type URL (or URI in Data model v1) or objects
            // The base context is the first entry in the set which is VC context URL (or URI in Data model v1)
            if let contextArray = credential["@context"] as? [Any], let contextValue = contextArray.first as? String {
                context.insert(contextValue)
            }
        }
        
        return UnsignedLdpVPToken(context : Array(context),
                                  type : ["VerifiablePresentation"],
                                  verifiableCredential: self.verifiableCredential.map { $0.mapValues { AnyCodable($0) } },
                                  id: self.id,
                                  holder: self.holder)
    }
}
