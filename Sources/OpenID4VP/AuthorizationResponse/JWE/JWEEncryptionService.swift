import Foundation

struct JWEEncryptionService {
    let config: JWEEncryptionConfig
    let jwk: JWK
    static let className = String(describing: JWEEncryptionService.self)
    
    init(config: JWEEncryptionConfig, jwk: JWK) {
        self.config = config
        self.jwk = jwk
    }
    
    func encryptPayload(_ payload: String) throws -> String {
        
        let algorithm = try getAlgorithm()
        let encryption = try getEncryption()
        
        guard let publicKeyData = Data(base64Encoded: makeBase64Standard(jwk.x)) else {
            throw Logger.handleException(exceptionType: "PublicKeyConversionFailed", className: JWEEncryptionService.className)
        }
        
        let contentEncryptionKey = try algorithm.deriveKey(publicKey: publicKeyData)
        
        guard let payloadData = payload.data(using: .utf8) else {
            throw Logger.handleException(exceptionType: "PayloadConversionFailed", className: JWEEncryptionService.className)
        }
        
        let (ciphertext, nonce, tag) = try encryption.encrypt(payloadData, with: contentEncryptionKey)
        
        var header = algorithm.getJWEHeader(config: config, jwk: jwk)
        
        if var epk = header["epk"] as? [String: Any] {
            epk["x"] = algorithm.getEphemeralPublicKey()
            header["epk"] = epk
        }
        
        return try encodeJWEComponents(
            header: header,
            encryptedKey: algorithm.getEncryptedKey(),
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }
    
    func getAlgorithm() throws -> JWEAlgorithm {
        switch config.alg {
        case "ECDH-ES":
            return ECDHESAlgorithm()
        default:
            throw Logger.handleException(exceptionType: "UnsupportedKeyExchangeAlgorithm", className: JWEEncryptionService.className)
        }
    }
    
    func getEncryption() throws -> JWEEncryption {
        switch config.enc {
        case "A256GCM":
            return AESGCMEncryption()
        default:
            throw Logger.handleException(exceptionType: "UnsupportedEncryptionAlgorithm", className: JWEEncryptionService.className)
        }
    }
}
