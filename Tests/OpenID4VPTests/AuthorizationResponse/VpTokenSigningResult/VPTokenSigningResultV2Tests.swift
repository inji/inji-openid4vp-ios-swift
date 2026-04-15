import XCTest
@testable import OpenID4VP

final class VPTokenSigningResultV2Tests: XCTestCase {

    func testInitStoresSignedData() {
        let result = VPTokenSigningResultV2(signedData: "signed-payload")
        XCTAssertEqual(result.signedData, "signed-payload")
    }

    func testEncodesToJSON() throws {
        let result = VPTokenSigningResultV2(signedData: "signed-payload")
        let data = try JSONEncoder().encode(result)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(json["signedData"] as? String, "signed-payload")
    }

    func testDecodesFromJSON() throws {
        let json = #"{"signedData":"signed-payload"}"#.data(using: .utf8)!
        let result = try JSONDecoder().decode(VPTokenSigningResultV2.self, from: json)
        XCTAssertEqual(result.signedData, "signed-payload")
    }

    func testEncodeDecode() throws {
        let original = VPTokenSigningResultV2(signedData: "round-trip-data")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(VPTokenSigningResultV2.self, from: data)
        XCTAssertEqual(decoded.signedData, original.signedData)
    }

    func testAcceptsEmptySignedData() {
        let result = VPTokenSigningResultV2(signedData: "")
        XCTAssertEqual(result.signedData, "")
    }
}
