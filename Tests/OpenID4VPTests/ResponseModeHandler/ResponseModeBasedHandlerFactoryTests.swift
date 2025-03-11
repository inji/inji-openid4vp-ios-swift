//
//  ResponseModeBasedHandlerFactoryTests.swift
//  
//
//  Created by Kiruthika Jeyashankar on 11/03/25.
//

import XCTest
@testable import OpenID4VP

final class ResponseModeBasedHandlerFactoryTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testThrowErrorWhenResponseModeIsNotSupportedOnGettingResponseModeHandler() throws {
        XCTAssertThrowsError(try ResponseModeBasedHandlerFactory.get(responseMode: "fragment")) { error in
            XCTAssertEqual("Given response_mode - fragment is not supported", error.localizedDescription)
        }
    }
}
