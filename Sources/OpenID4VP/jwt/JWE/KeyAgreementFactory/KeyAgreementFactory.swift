class KeyAgreementFactory {
    static let className = String(describing: KeyAgreementFactory.self)
    
    static func createKeyAgreement(for jwk: JWK) throws -> JWEKeyAgreement {
        switch (jwk.kty, jwk.crv) {
        case ("OKP", "X25519"):
            return X25519KeyAgreement()
        default:
            throw UnsupportedKeyAgreementAlgorithm(message: "Required Key Agreement algorithm is not supported.",className: KeyAgreementFactory.className)
        }
    }
}
