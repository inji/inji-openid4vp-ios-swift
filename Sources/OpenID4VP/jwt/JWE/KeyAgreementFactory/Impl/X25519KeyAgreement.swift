import Foundation
import JSONWebKey
import CryptoKit

class X25519KeyAgreement: JWEKeyAgreement {
    static let className = String(describing: X25519KeyAgreement.self)
    private var ephemeralKeyPair: (privateKey: Curve25519.KeyAgreement.PrivateKey,
                                   publicKey: Curve25519.KeyAgreement.PublicKey)?
    
    func deriveKey(publicKey: Data) throws -> SymmetricKey {
        do {
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            
            ephemeralKeyPair = (privateKey, privateKey.publicKey)
            
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            
            return sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: "ECDH-ES+A256GCM".data(using: .utf8)!,
                sharedInfo: Data(),
                outputByteCount: 32
            )
        } catch {
            throw wrapError(
                error,
                customError: { msg in KeyAgreementFailed(message: msg, className: X25519KeyAgreement.className) }
            )
        }
    }
    
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
            let partyUInfo = Data(apu.utf8)
            let partyVInfo = Data(apv.utf8)
            let keyLength = 32 // 256-bit AES key
            
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
            data.append(algorithmID)
            data.append(partyUInfo)
            data.append(partyVInfo)
            data.append(suppPubInfo)
            data.append(suppPrivInfo)
            
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
}
