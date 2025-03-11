import XCTest
@testable import OpenID4VP

final class AuthorizationResponseTests: XCTestCase {
    
    func testConstructVpForSigning() throws {
        
        let verifiableCredentials: [String: [String]] = ["key1": ["cred1", "cred2"], "key2": ["cred3"]]
        
        let vpTokenString = try AuthorizationResponse.constructVpForSigning(verifiableCredentials)
        
        let jsonData = Data(vpTokenString.utf8)
        let decodedVpToken = try JSONDecoder().decode(VpTokenForSigning.self, from: jsonData)
        
        XCTAssertEqual(decodedVpToken.verifiableCredential.count, ["cred1", "cred2", "cred3"].count)
        XCTAssertEqual(decodedVpToken.holder, "")
        XCTAssertEqual(decodedVpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(decodedVpToken.context, ["https://www.w3.org/2018/credentials/v1"])
        XCTAssertNotNil(UUID(uuidString: decodedVpToken.id), "ID should be a valid UUID")
        XCTAssertEqual(AuthorizationResponse.verifiableCredentials, ["key1": ["cred1", "cred2"], "key2": ["cred3"]])
    }
}
