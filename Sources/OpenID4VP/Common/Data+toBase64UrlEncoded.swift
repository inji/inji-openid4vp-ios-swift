//
//  File.swift
//  
//
//  Created by Kiruthika Jeyashankar on 11/03/25.
//

import Foundation

extension Data {
    func toBase64UrlEncoded() -> String {
        return base64URLEscaped(self.base64EncodedString())
    }
}
