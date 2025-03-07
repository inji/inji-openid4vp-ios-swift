import XCTest
@testable import OpenID4VP

final class AuthorizationResponseUtilsTests: XCTestCase {
    
    func testCreateDescriptorMapSuccess() {

        let verifiableCredentials: [String: [String]] = [
            "id1": ["cred1", "cred2"],
            "id2": ["cred3"]
        ]
        
        let descriptorMap = createDescriptorMap(verifiableCredentials: verifiableCredentials)

        XCTAssertEqual(descriptorMap.count, 3)

        let sortedDescriptorMap = descriptorMap.sorted {
            $0.id < $1.id || ($0.id == $1.id && $0.path < $1.path)
        }
        
        XCTAssertEqual(sortedDescriptorMap[0].id, "id1")
        XCTAssertEqual(sortedDescriptorMap[0].format, .ldp_vp)
        XCTAssertEqual(sortedDescriptorMap[0].path, "$.verifiableCredential[0]")

        XCTAssertEqual(sortedDescriptorMap[1].id, "id1")
        XCTAssertEqual(sortedDescriptorMap[1].format, .ldp_vp)
        XCTAssertEqual(sortedDescriptorMap[1].path, "$.verifiableCredential[1]")

        XCTAssertEqual(sortedDescriptorMap[2].id, "id2")
        XCTAssertEqual(sortedDescriptorMap[2].format, .ldp_vp)
        XCTAssertEqual(sortedDescriptorMap[2].path, "$.verifiableCredential[2]")
    }
}
