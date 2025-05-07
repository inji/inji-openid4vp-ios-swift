//
//  File.swift
//  OpenID4VP
//
//  Created by Kiruthika Jeyashankar on 24/04/25.
//

import Foundation
import SwiftCBOR

fileprivate let className = "CBORUtils"

func decodeCBOR(base64EncodedInput : String) throws -> CBOR? {
    do{
        guard let decodedBase64Data = Data(base64EncodedURLSafe: base64EncodedInput) else {
            print("Invalid base64 URL string provided")
            throw Logger.handleException(exceptionType: "InvalidData", message: "Invalid base64 URL string provided", className: String(describing: className))
        }
        
        let inputToCBORDecode = Array(decodedBase64Data)
        let cborDecodedData = try CBOR.decode(inputToCBORDecode)
        return cborDecodedData
    }
    catch let error {
        throw Logger.handleException(exceptionType: "InvalidData", message: "Error while decoding input - \(error)", className: String(describing: CBOR.self))
    }
}

func cborEncode(_ input: CBOR) -> [UInt8] {
    return CBOR.encode(input)
}

func toCBOR(_ input: Data) -> CBOR {
    return CBOR.byteString([UInt8](input))
}

// creates #6.24 (bstr .cbor input)
func wrapCBORInputWithTag24(input: CBOR) -> CBOR? {
    guard let encodedInput: [UInt8]? = SwiftCBOR.CBOR.encode(input) else {
        print("Failed to encode input CBOR")
        return nil
    }
    let cborTaggedValue: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(encodedInput!))
    
    return cborTaggedValue
}

internal func toCBORArray(_ input: [CBOR]) -> CBOR {
    return CBOR.array(input.map { ($0) })
}

func getValueFromCBORMap(cborMap: CBOR, key: String) -> CBOR? {
    guard case let .map(items) = cborMap else { return nil }
    
    let cborKey = CBOR.utf8String(key)
    return items[cborKey]
}

func extractStringFromCBOR(_ cbor: CBOR) -> String? {
    if case let .utf8String(str) = cbor {
        return str
    }
    return nil
}

func cborToByteString(cbor: CBOR) -> String {
    let encodedData : [UInt8] = CBOR.encode(cbor)
    
    return encodedData.map { String(format: "%02x", $0) }.joined()
}

func mapSigningAlgorithmToProtectedAlg(algorithm: String) throws -> UInt64 {
    switch algorithm {
    case "ES256":
        return 6
    default:
        throw NSError(domain: "Unsupported signing algorithm: \(algorithm)", code: 0, userInfo: nil)
    }
}
