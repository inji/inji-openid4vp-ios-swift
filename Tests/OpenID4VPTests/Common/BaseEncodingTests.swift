import XCTest
@testable import OpenID4VP

final class BaseEncodingTests: XCTestCase {

    // MARK: - Leading zero bytes

    func testEncodesEmptyDataToEmptyString() {
        XCTAssertEqual(BaseEncoding.base58BtcEncode(bytes: Data()), "")
    }

    func testEncodesLeadingZeroBytesToLeadingOnes() {
        let data = Data([0x00, 0x00, 0x01])
        let result = BaseEncoding.base58BtcEncode(bytes: data)
        XCTAssertTrue(result.hasPrefix("11"), "Expected two leading '1' chars for two leading zero bytes, got: \(result)")
    }

    func testEncodesAllZeroBytesToAllOnes() {
        let data = Data([0x00, 0x00, 0x00])
        XCTAssertEqual(BaseEncoding.base58BtcEncode(bytes: data), "111")
    }

    // MARK: - Known vectors

    func testEncodesSingleByteOne() {
        // 0x01 → "2" (index 1 in the base-58 alphabet)
        XCTAssertEqual(BaseEncoding.base58BtcEncode(bytes: Data([0x01])), "2")
    }

    func testEncodesSingleByteFf() {
        // 0xFF = 255 → 4*58 + 23 → alphabet[4]="5", alphabet[23]="Q" → "5Q"
        XCTAssertEqual(BaseEncoding.base58BtcEncode(bytes: Data([0xFF])), "5Q")
    }

    func testEncodesHelloWorld() {
        // Known base58btc encoding of "Hello World"
        let input = Data("Hello World".utf8)
        XCTAssertEqual(BaseEncoding.base58BtcEncode(bytes: input), "JxF12TrwUP45BMd")
    }

    func testEncodesAsciiString() {
        // Known base58btc encoding of "abc"
        let input = Data("abc".utf8)
        XCTAssertEqual(BaseEncoding.base58BtcEncode(bytes: input), "ZiCa")
    }

    // MARK: - Alphabet characters

    func testOutputOnlyContainsBase58BtcAlphabetCharacters() {
        let alphabet = Set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        let input = Data((0...255).map { UInt8($0) })
        let result = BaseEncoding.base58BtcEncode(bytes: input)
        for char in result {
            XCTAssertTrue(alphabet.contains(char), "Unexpected character '\(char)' in output")
        }
    }

    func testDoesNotContainExcludedCharacters() {
        let excluded: Set<Character> = ["0", "O", "I", "l"]
        let input = Data((0...255).map { UInt8($0) })
        let result = BaseEncoding.base58BtcEncode(bytes: input)
        for char in result {
            XCTAssertFalse(excluded.contains(char), "Excluded character '\(char)' found in output")
        }
    }

    // MARK: - Determinism

    func testEncodingIsDeterministic() {
        let input = Data([0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(
            BaseEncoding.base58BtcEncode(bytes: input),
            BaseEncoding.base58BtcEncode(bytes: input)
        )
    }

    func testDifferentInputsProduceDifferentOutputs() {
        let a = BaseEncoding.base58BtcEncode(bytes: Data([0x01]))
        let b = BaseEncoding.base58BtcEncode(bytes: Data([0x02]))
        XCTAssertNotEqual(a, b)
    }
}
