
//
//  separately.swift
//  OpenID4VP
//
//  Created by Kiruthika Jeyashankar on 07/05/25.
//


import Foundation
import CryptoKit
import SwiftCBOR

func base64UrlEncode(_ input: Data) -> String {
    //TODO: Move this encoding logic to encoder class separately
    let base64String = input.base64EncodedString()
    let base64urlEncoded = base64String
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    
    return base64urlEncoded
}
