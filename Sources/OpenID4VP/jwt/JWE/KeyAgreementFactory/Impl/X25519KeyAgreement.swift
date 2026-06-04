import Foundation
import JSONWebKey
import CryptoKit

class X25519KeyAgreement: JWEKeyAgreement {
    static let className = String(describing: X25519KeyAgreement.self)
    private var ephemeralKeyPair: (privateKey: Curve25519.KeyAgreement.PrivateKey,
                                   publicKey: Curve25519.KeyAgreement.PublicKey)?
    
    func deriveKey(publicKey: Data,
                   algorithm: String = "A256GCM",
                   apu: String,
                   apv: String) throws -> SymmetricKey {
        do {
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            
            ephemeralKeyPair = (privateKey, privateKey.publicKey)
            
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            
            let algorithmID = Data(algorithm.utf8)
            
            guard let partyUInfo = Data(base64UrlEncoded: apu) else {
                throw Base64DecodingFailed(message: "Failed to decode producer info (apu)", className: X25519KeyAgreement.className)
            }
            guard let partyVInfo = Data(base64UrlEncoded: apv) else {
                throw Base64DecodingFailed(message: "Failed to decode recipient info (apv)", className: X25519KeyAgreement.className)
            }
            
            let keyLength = try getKeyLength(algorithm: algorithm)
            
            // Convert key length (in bits) to big-endian bytes
            var bitsBE = UInt32(keyLength * 8).bigEndian
            let suppPubInfo = withUnsafeBytes(of: &bitsBE) { Data($0) }
            
            let cek = concatKDF(
                sharedSecret: sharedSecret,
                keyLength: keyLength,
                algorithmID: algorithmID,
                partyUInfo: partyUInfo,
                partyVInfo: partyVInfo,
                suppPubInfo: suppPubInfo
            )
            return cek
        } catch {
            throw wrapError(
                error,
                customError: { msg in KeyAgreementFailed(message: msg, className: X25519KeyAgreement.className) }
            )
        }
    }
    
    private func concatKDF(
        sharedSecret: SharedSecret,
        keyLength: Int,                // bytes
        algorithmID: Data,
        partyUInfo: Data,
        partyVInfo: Data,
        suppPubInfo: Data,
        suppPrivInfo: Data = Data()
    ) -> SymmetricKey {
        var otherInfo = Data()
        
        appendLengthPrefixed(algorithmID, to: &otherInfo)
        appendLengthPrefixed(partyUInfo, to: &otherInfo)
        appendLengthPrefixed(partyVInfo, to: &otherInfo)
        
        otherInfo.append(suppPubInfo)
        otherInfo.append(suppPrivInfo)
        
        var derivedKey = Data()
        var counter: UInt32 = 1
        
        // Raw shared secret bytes
        let zData = sharedSecret.withUnsafeBytes { Data($0) }
        
        while derivedKey.count < keyLength {
            var data = Data()
            // Counter in big-endian
            var ctr = counter.bigEndian
            data.append(Data(bytes: &ctr, count: 4))
            
            // Append Z and OtherInfo
            data.append(zData)
            data.append(otherInfo)
            
            // Hash
            let hash = SHA256.hash(data: data)
            derivedKey.append(contentsOf: hash)
            counter += 1
        }
        
        return SymmetricKey(data: derivedKey.prefix(keyLength))
    }
    
    func getEphemeralPublicKey() -> [String: Any]? {
        guard let publicKey = ephemeralKeyPair?.publicKey else { return nil }
        return [
            "kty": "OKP",
            "crv": "X25519",
            "x": base64URLEscaped(publicKey.rawRepresentation.base64EncodedString())
        ]
    }
    
    func getJWEHeader(alg: String, enc: String, jwk: JWK, producerInfo: String, recipientInfo: String) -> [String: Any] {
        return [
            "alg": alg,
            "enc": enc,
            "kid": jwk.keyID ?? "",
            "apu": producerInfo,
            "apv": recipientInfo,
        ]
    }
    
    func getEncyptionKey() -> String {
        return ""
    }
    
    private func appendLengthPrefixed(_ value: Data, to buffer: inout Data) {
        var valueLength = UInt32(value.count).bigEndian
        buffer.append(Data(bytes: &valueLength, count: 4))
        buffer.append(value)
    }
    
    private func getKeyLength(algorithm: String) throws -> Int {
        let algorithmValue = EncryptionMethod.fromValue(algorithm)
        switch algorithmValue {
        case .a256GCM:
            return 32 // 256-bit AES key
        default:
            throw UnsupportedOperationException(message: "Unsupported content encryption algorithm: \(algorithm)", className: X25519KeyAgreement.className)
        }
    }
}
