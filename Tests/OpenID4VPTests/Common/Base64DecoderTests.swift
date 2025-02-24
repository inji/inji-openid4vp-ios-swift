import XCTest
@testable import OpenID4VP

class
rTests: XCTestCase {
    //Decode base64 string to JSON
    
    func testDecodeBase64ToJSONSuccessCase() throws {
        let json = "{\"key\":\"value\"}"
        let base64String = Data(json.utf8).base64EncodedString()
        
        do {
            let decodedJSON = try Base64Decoder.decodeBase64ToJSON(base64String)
            XCTAssertEqual(decodedJSON["key"] as? String, "value")
        } catch {
            XCTFail("Expected to decode successfully, but failed with error: \(error)")
        }
    }
    
    func testDecodeBase64ToJSONWithInvalidBase64() {
        let invalidBase64 = "%%InvalidBase64%%"
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(invalidBase64)) { error in
            XCTAssertEqual("Error occurred while decoding ", error.localizedDescription)
        }
    }
    
    func testDecodeBase64ToJSONWithEmptyBase64() {
        let emptyBase64 = ""
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(emptyBase64)) { error in
            XCTAssertEqual("Json Decoding failed for  due to this error: JWT Decoding to json failed.", error.localizedDescription)
        }
    }
    
    func testDecodeBase64ToJSONWithNonJSONData() {
        let nonJSONString = "This is not JSON"
        let base64String = Data(nonJSONString.utf8).base64EncodedString()
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(base64String)) { error in
            XCTAssertEqual("Json Decoding failed for  due to this error: JWT Decoding to json failed.", error.localizedDescription)
        }
    }
    
    func testDecodeBase64ToJSONWithCorruptedJSON() {
        let corruptedJSON = "{\"key\":\"value" //Invalid JSON - Missing closing bracket
        let base64String = Data(corruptedJSON.utf8).base64EncodedString()
        
        XCTAssertThrowsError(try Base64Decoder.decodeBase64ToJSON(base64String)) { error in
            XCTAssertEqual("Json Decoding failed for  due to this error: JWT Decoding to json failed.", error.localizedDescription)
        }
    }
    
    //Test convert base64 to bas64 url safe
    
    func testMakeBase64Standard() {
        let input = "U29t-_"
        let expected = "U29t+/=="
        
        let output = Base64Decoder.makeBase64Standard(input)
        
        XCTAssertEqual(output, expected, "URL-safe characters should be converted and padding should be added")
    }
}
