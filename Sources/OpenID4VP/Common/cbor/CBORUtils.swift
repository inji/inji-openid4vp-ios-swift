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


// created #6.24 (bstr .cbor input)
func wrapCBORInputWithTag24(input: CBOR) -> CBOR? {
    //    CBOR.tagged(.init(rawValue: 24), .byteString(CBOR.encode(devicesNamespaces)))
    // Explicitly use SwiftCBOR.CBOR.encode to avoid ambiguity
    guard let encodedInput: [UInt8]? = SwiftCBOR.CBOR.encode(input) else {
        print("Failed to encode input CBOR")
        return nil
    }
    
    // Wrap the encoded byte string with CBOR tag (24)
    let cborTaggedValue: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(encodedInput!))
    
    // Encode the tagged CBOR object to bytes
    //    return SwiftCBOR.CBOR.encode(cborTaggedValue)
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
