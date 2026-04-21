import XCTest
@testable import OpenID4VP

final class VPTokenSigningResultTests: XCTestCase {


    func testInitStoresSignedData() {
        let result = VPTokenSigningResult(signedData: "signed-payload")
        XCTAssertEqual(result.signedData, "signed-payload")
    }

    func testEncodesToJSON() throws {
        let result = VPTokenSigningResult(signedData: "signed-payload")
        let data = try JSONEncoder().encode(result)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["signedData"] as? String, "signed-payload")
    }

    func testDecodesFromJSON() throws {
        let json = #"{"signedData":"signed-payload"}"#.data(using: .utf8)!
        let result = try JSONDecoder().decode(VPTokenSigningResult.self, from: json)
        XCTAssertEqual(result.signedData, "signed-payload")
    }

    func testEncodeDecode() throws {
        let original = VPTokenSigningResult(signedData: "round-trip-data")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(VPTokenSigningResult.self, from: data)
        XCTAssertEqual(decoded.signedData, original.signedData)
    }

    func testAcceptsEmptySignedData() {
        let result = VPTokenSigningResult(signedData: "")
        XCTAssertEqual(result.signedData, "")
    }
}
