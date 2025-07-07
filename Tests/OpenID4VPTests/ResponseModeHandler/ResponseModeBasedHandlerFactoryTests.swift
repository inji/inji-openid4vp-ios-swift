import XCTest
@testable import OpenID4VP

final class ResponseModeBasedHandlerFactoryTests: XCTestCase {
    func testThrowErrorWhenResponseModeIsNotSupportedOnGettingResponseModeHandler() throws {
        XCTAssertThrowsError(try ResponseModeBasedHandlerFactory.get(responseMode: "fragment")) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Given response_mode - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testReturnOfResponseResponseHandlerWhenFactoryGetIsInvoked() throws {
        let responseModeHandler1: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "direct_post")
        let responseModeHandler2: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "direct_post.jwt")
        
        XCTAssertTrue(responseModeHandler1 is DirectPostResponseModeHandler)
        XCTAssertTrue(responseModeHandler2 is DirectPostJwtResponseModeHandler)
    }
}
