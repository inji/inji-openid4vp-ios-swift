import Foundation
@testable import OpenID4VP
import XCTest

func assertJsonString(expected jsonString1: String, actual jsonString2: String, strict: Bool = true, file: StaticString = #file, line: UInt = #line) {
    do {
        guard let data1 = jsonString1.data(using: .utf8),
              let data2 = jsonString2.data(using: .utf8) else {
            XCTFail("Invalid JSON string encoding", file: file, line: line)
            return
        }

        let json1 = try JSONSerialization.jsonObject(with: data1, options: []) as? [String: Any]
        let json2 = try JSONSerialization.jsonObject(with: data2, options: []) as? [String: Any]

        XCTAssertNotNil(json1, "Failed to parse first JSON string", file: file, line: line)
        XCTAssertNotNil(json2, "Failed to parse second JSON string", file: file, line: line)

        if let json1 = json1, let json2 = json2 {
            assertDictionariesEqual(expected: json1, actual: json2, file: file, line: line, strict: strict)
        }
    } catch {
        XCTFail("JSON deserialization failed with error: \(error)", file: file, line: line)
    }
}

//Assert two dictionaries
func assertDictionariesEqual(expected: [String: Any], actual: [String: Any]?, file: StaticString = #file, line: UInt = #line, strict: Bool = true) {
    guard let actualDict = actual else {
        XCTFail("Actual is nil", file: file, line: line)
        return
    }
    
    func isEqual(_ lhs: Any?, _ rhs: Any?) -> Bool {
        switch (lhs, rhs) {
        case let (lhs as String, rhs as String): return lhs == rhs
        case let (lhs as Int, rhs as Int): return lhs == rhs
        case let (lhs as Double, rhs as Double): return lhs == rhs
        case let (lhs as Bool, rhs as Bool): return lhs == rhs
        case let (lhs as NSNull, rhs as NSNull):
            return lhs == rhs
        case let (lhs as [String: Any], rhs as [String: Any]): return dictionariesEqual(lhs, rhs, strict: strict)
        case let (lhs as [Any], rhs as [Any]): return arraysEqual(lhs, rhs)
        case let (lhs as any RawRepresentable, rhs as any RawRepresentable):
            return isEqual(lhs.rawValue, rhs.rawValue)
        case let (lhs as Encodable, rhs as Encodable):
            do {
                let encoder = JSONEncoder()
                let jsonData1 = try encoder.encode(lhs)
                let jsonData2 = try encoder.encode(rhs)
                
                let dict1 = try JSONSerialization.jsonObject(with: jsonData1, options: []) as? [String: Any]
                let dict2 = try JSONSerialization.jsonObject(with: jsonData2, options: []) as? [String: Any]
                
                XCTAssertNotNil(dict1, "Failed to convert instance1 to dictionary", file: file, line: line)
                XCTAssertNotNil(dict2, "Failed to convert instance2 to dictionary", file: file, line: line)
                
                assertDictionariesEqual(expected: dict1 ?? [:], actual: dict2, file: file, line: line)
                return true
            } catch {
                print("error - \(error) occurred during conversion")
                return false
            }
        default: return "\(String(describing: lhs))"  == "\(String(describing: rhs))"
        }
    }
    
    func dictionariesEqual(_ lhs: [String: Any], _ rhs: [String: Any], strict: Bool = true) -> Bool {
        if strict == true && lhs.count != rhs.count  { return false }
        
        return lhs.allSatisfy { key, value in
            guard let rhsValue = rhs[key] else { return false }
            return isEqual(value, rhsValue)
        }
    }
    
    func arraysEqual(_ lhs: [Any], _ rhs: [Any]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).allSatisfy { isEqual($0, $1) }
    }
    
    if strict {
        //TODO: add containsAll check to enhance assertion
        XCTAssertEqual(expected.count, actualDict.count, "Dictionary sizes are different", file: file, line: line)
    }
    
    for (key, expectedValue) in expected {
        guard let actualValue = actualDict[key] else {
            XCTFail("Missing key '\(key)' in actual dictionary", file: file, line: line)
            continue
        }
        
        XCTAssertTrue(isEqual(expectedValue, actualValue), "Mismatch for key '\(key)'. Expected: \(expectedValue), but got: \(actualValue)", file: file, line: line)
    }
}

func assertAsyncThrowsError<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (_ error: any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("Expected error to be thrown, but no error was thrown. \(message())", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

func assertAsyncNoThrowsError<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
    } catch {
        XCTFail("Expected no error to be thrown, but an error was thrown: \(error). \(message())", file: file, line: line)
    }
}

func XCTAssertNoThrowAndVerify<T>(_ expression: @autoclosure () throws -> T,
                                  file: StaticString = #filePath,
                                  line: UInt = #line,
                                  _ assertions: (T) -> Void) {
    do {
        let result = try expression()
        assertions(result)
    } catch {
        XCTFail("Expression threw an error: \(error)", file: file, line: line)
    }
}
