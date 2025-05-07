//
//  File.swift
//  OpenID4VP
//
//  Created by Kiruthika Jeyashankar on 24/04/25.
//

import Foundation
import SwiftCBOR

func decodeCBOR(input : String) -> CBOR? {
    do{
        guard let decodedBase64Data = Data(base64EncodedURLSafe: input) else {
            print("Invalid base64 URL string provided")
            return nil
            //            throw decodeByteArrayError.customError(description: "Error while base64 url decoding the data")
        }
        
        let inputToCBORDecode = Array(decodedBase64Data)
        if let cborDecodedData = try? CBOR.decode(inputToCBORDecode) {
            return cborDecodedData
        } else {
            print("Error while CBOR decoding the data")
            return nil
            //            throw decodeError.customError(description: "CBOR decoding failed")
        }
    }
    catch let error {
        print("error occurred while parsing  data - \(error)")
        return nil
        //        throw decodeByteArrayError.customError(description: "error occurred while parsing  data - \(error.localizedDescription)")
    }
}

//
func encodeToCBOR() {
    // Example array of key-value pairs
    let elements: [(String, String)] = [("key1", "value1"), ("key2", "value2")]
    
    // Step 1: Convert the array into a CBOR dictionary
    let cborMap: [CBOR: CBOR] = Dictionary(uniqueKeysWithValues: elements.map { key, value in
        (CBOR.utf8String(key), CBOR.utf8String(value))
    })
    
    // Step 2: Create a CBOR map
    let cborData = CBOR.map(cborMap)
    let encodedData =    CBOR.encode(cborMap)
    
    //    // Step 3: Encode the CBOR map
    //    guard let encodedData = try? CBOR.encode(cborData) else {
    //        fatalError("Failed to encode CBOR data")
    //    }
    let hexString = encodedData.map { String(format: "%02x", $0) }.joined()
    
    // Output the encoded CBOR data
    print("CBOR Data: \(hexString)")
}

func createEmbeddedEncodedCborWithTag( data: [String: Any]) -> [UInt8]  {
    // Convert the input dictionary to CBOR format
    let cborMap = CBOR.map(data.reduce(into: [CBOR: CBOR]()) { result, item in
        result[CBOR.utf8String(item.key)] = CBOR.utf8String("\(item.value)")
    })
    
    
    // Create a CBOR tagged object
    guard let taggedData = wrapCBORInputWithTag24(input: cborMap) else {
        print("error")
        return []
    }
    let encodedData :[UInt8] = SwiftCBOR.CBOR.encode(taggedData)
    
    return encodedData
    
    let hexString = encodedData.map { String(format: "%02x", $0) }.joined()
    //
    print("CBOR Data: \(hexString)")
}

func createEmbeddedEncodedCborWithTag( data: CBOR) -> [UInt8]  {
    // Create a CBOR tagged object
    guard let taggedData = wrapCBORInputWithTag24(input: data) else {
        print("error")
        return []
    }
    let encodedData :[UInt8] = SwiftCBOR.CBOR.encode(taggedData)
    
    return encodedData
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

func decodeCBOR(base64UrlEncodedData: String) throws -> CBOR?{
    guard let decodedBase64Data = Data(base64EncodedURLSafe: base64UrlEncodedData) else {
        print("Error decoding the input")
        return nil
    }
    
    let inputToCBORDecode = Array(decodedBase64Data)
    if let cborDecodedData = try? CBOR.decode(inputToCBORDecode) {
        return cborDecodedData
    } else {
        print("Error decoding the input")
        return nil
    }
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
