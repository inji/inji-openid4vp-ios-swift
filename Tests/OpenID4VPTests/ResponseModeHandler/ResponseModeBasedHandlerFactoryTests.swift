import XCTest
@testable import OpenID4VP

final class ResponseModeBasedHandlerFactoryTests: XCTestCase {
    func testThrowErrorWhenResponseModeIsNotSupportedOnGettingResponseModeHandler() throws {
        XCTAssertThrowsError(try ResponseModeBasedHandlerFactory.get(responseMode: "fragment")) { error in
            XCTAssertEqual("Given response_mode - fragment is not supported", error.localizedDescription)
        }
    }
    
    func testReturnOfResponseResponseHandlerWhenFactoryGetIsInvoked() throws {
        let responseModeHandler1: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "direct_post")
        let responseModeHandler2: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "direct_post.jwt")
        
        XCTAssertTrue(responseModeHandler1 is DirectPostResponseModeHandler)
        XCTAssertTrue(responseModeHandler2 is DirectPostJwtResponseModeHandler)
    }
}
