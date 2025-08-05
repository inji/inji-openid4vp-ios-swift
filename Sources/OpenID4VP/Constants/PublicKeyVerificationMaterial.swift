//
//  File.swift
//  OpenID4VP
//
//  Created by Kiruthika J on 05/08/25.
//

import Foundation

enum PublicKeyVerificationMaterial : String, Codable, CaseIterable {
    case jwk = "publicKeyJwk"
    case hex = "publicKeyHex"
    case multibase = "publicKeyMultibase"
    case pem = "publicKeyPem"
}
