import Foundation

private let keyBindingJWT = "kb+jwt"

struct UnsignedSdJWTVPTokenBuilder : UnsignedVPTokenBuilder {
    private let clientId: String
    private let nonce: String
    private let sdJWTCredentials: [String]
    private let networkManager: any NetworkManaging
    
    private static let className = "UnsignedSdJWTVPTokenBuilder"
    
    init(clientId: String, authorizationRequestNonce: String, credentials: [String], networkManager: any NetworkManaging = NetworkManager()) {
        self.clientId = clientId
        self.nonce = authorizationRequestNonce
        self.sdJWTCredentials = credentials
        self.networkManager = networkManager
    }
    
    func build() async throws -> [String : Any] {        
        var uuidToSdJWT = [String: String]()
        var uuidToUnsignedKBJWT = [String: String]()
        
        for credential in sdJWTCredentials {
            let uuid = UUIDGenerator.generateUUID()
            uuidToSdJWT[uuid] = credential
            
            let sdJWT = credential.split(separator: "~")[0]
            let sdJWTPayload = try JWSHandler.extractDataJsonFromJws(jws: String(sdJWT), jwsPart: .payload)
            
            guard let confirmationKeyClaim = sdJWTPayload["cnf"] as? [String: Any], !confirmationKeyClaim.isEmpty else {
                continue
            }
            
            var jwtSigningALgorithm: String = ""
            if confirmationKeyClaim.keys.contains("kid") {
                let didResolver = DidPublicKeyResolver(networkManager: networkManager)
                let confirmationKey = try await didResolver.resolve(uri: confirmationKeyClaim["kid"] as! String, keyId: nil)
                jwtSigningALgorithm = extractSigningAlgorithm(from: confirmationKey)
            } else {
                throw UnsupportedOperationException(message: "Unsupported cnf format, only 'kid' is supported", className: Self.className, code: "unsupported_operation")
            }
            
            let jwtHeader = [
                "alg": jwtSigningALgorithm,
                "typ": keyBindingJWT
            ]
            
            let sdHashAlgorithm = sdJWTPayload["_sd_alg"] as? String ?? HashAlgorithm.sha256.rawValue
            let sdHash = try hashData(credential, hashAlgorithm: sdHashAlgorithm, className: Self.className).toBase64UrlEncoded()
            
            let jwtPayload : [String: Any] = [
                "iat": Int(Date().timeIntervalSince1970),
                "aud": clientId,
                "nonce": nonce,
                "sd_hash": sdHash
            ]
            
            let unsignedJWT = try JWSHandler.createUnsignedJWS(header: jwtHeader, payload: jwtPayload)
            
            uuidToUnsignedKBJWT[uuid] = unsignedJWT
        }
        
        return [
            "unsignedVPToken": UnsignedSdJWTVPToken(uuidToUnsignedKBT: uuidToUnsignedKBJWT),
            "vpTokenSigningPayload": uuidToSdJWT
        ]
    }
}
