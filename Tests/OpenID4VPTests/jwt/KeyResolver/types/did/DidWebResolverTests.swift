//import XCTest
//@testable import OpenID4VP
//
//final class DidWebResolverTests: XCTestCase {
//    let mockNetworkManager = MockNetworkManager()
//    
//    let didUrl = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs"
//    
//    func testResolveDidUrlToDidDocumentSuccessfully() async {
//        let didWebResolver = DidWebResolver(didUrl: didUrl, networkManager: mockNetworkManager)
//        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
//        
//        let didDocument = try! await didWebResolver.resolve()
//        
//        assertDictionariesEqual(expected: [
//            "assertionMethod": [
//                "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
//            ],
//            "service": [],
//            "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
//            "verificationMethod": [
//                [
//                    "publicKeyMultibase": "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
//                    "controller": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
//                    "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
//                    "type": "Ed25519VerificationKey2020",
//                    "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
//                ]
//            ],
//            "@context": [
//                "https://www.w3.org/ns/did/v1"
//            ],
//            "alsoKnownAs": [],
//            "authentication": [
//                "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
//            ]
//        ], actual: didDocument)
//    }
//    
//    func testDIDWebWithParamsPathQuertAndFragmentSection() async throws {
//        let testCases: [TestCase] = [
//            TestCase(input: "did:web:example.com;param=", expectedError: ""),
//            TestCase(input: "did:web:example.com;param=value", expectedError: ""),
//            TestCase(input: "did:web:example.com;param=value/user/profile?verified=true#contact", expectedError: "")
//        ]
//        
//        for testCase in testCases {
//            mockNetworkManager.setMockResponse(for: "https://example.com/.well-known/did.json", responseBody: didResponse)
//            let didWebResolver = DidWebResolver(didUrl: testCase.input, networkManager: mockNetworkManager)
//            
//            let didDocument = try await didWebResolver.resolve()
//            
//            assertDictionariesEqual(expected: [
//                "assertionMethod": [
//                    "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
//                ],
//                "service": [],
//                "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
//                "verificationMethod": [
//                    [
//                        "publicKeyMultibase": "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
//                        "controller": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
//                        "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
//                        "type": "Ed25519VerificationKey2020",
//                        "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
//                    ]
//                ],
//                "@context": [
//                    "https://www.w3.org/ns/did/v1"
//                ],
//                "alsoKnownAs": [],
//                "authentication": [
//                    "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
//                ]
//            ], actual: didDocument)
//        }
//    }
//    
//    func testConstructDIDUrlWithPath() async throws {
//        let testCases: [TestCase] = [
//            TestCase(input: "did:web:example.com:user", expectedOutput: "https://example.com/user/did.json"),
//            TestCase(input: "did:web:example.com:services:auth", expectedOutput: "https://example.com/services/auth/did.json"),
//            TestCase(input: "did:web:example.com:folder:anotherFolder", expectedOutput: "https://example.com/folder/anotherFolder/did.json")
//        ]
//        
//        for testCase in testCases {
//            mockNetworkManager.setMockResponse(for: testCase.expectedOutput!, responseBody: didResponse)
//            let didWebResolver = DidWebResolver(didUrl: testCase.input, networkManager: mockNetworkManager)
//            _ = try await didWebResolver.resolve()
//            
//            XCTAssertTrue(mockNetworkManager.recordedRequests.keys.contains(testCase.expectedOutput!),
//                                  "Expected request to \(testCase.expectedOutput!) but it was not recorded.")
//        
//        }
//    }
//    
//    func testConstructDIDUrlWithoutPath() async throws {
//        let testCases: [TestCase] = [
//            TestCase(input: "did:web:example.com", expectedOutput: "https://example.com/.well-known/did.json"),
//            TestCase(input: "did:web:sub.example.com", expectedOutput: "https://sub.example.com/.well-known/did.json")
//        ]
//        
//        for testCase in testCases {
//            mockNetworkManager.setMockResponse(for: testCase.expectedOutput!, responseBody: didResponse)
//            let didWebResolver = DidWebResolver(didUrl: testCase.input, networkManager: mockNetworkManager)
//            _ = try await didWebResolver.resolve()
//            
//            XCTAssertTrue(mockNetworkManager.recordedRequests.keys.contains(testCase.expectedOutput!),
//                                  "Expected request to \(testCase.expectedOutput!) but it was not recorded.")
//        }
//    }
//    
//    func testThrowErrorWhenDidUrlIsNonWebMethod() async {
//        let invalidDID = "did:jwk:z6MkXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
//        let didWebResolver = DidWebResolver(didUrl: invalidDID, networkManager: mockNetworkManager)
//        
//        do{
//            _ = try await didWebResolver.resolve()
//            XCTFail("Error - unsupportedDidUrl should be thrown but did not throw")
//        } catch {
//            assertOpenID4VPException(
//                error,
//                expectedMessage: "Given did url is not supported",
//                expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//    
//    func testThrowErrorWhenDidUrlIsEmptyString() async {
//        let invalidDID = ""
//        let didWebResolver = DidWebResolver(didUrl: invalidDID, networkManager: mockNetworkManager)
//        
//        do{
//            _ = try await didWebResolver.resolve()
//            XCTFail("Error - unsupportedDidUrl should be thrown but did not throw")
//        } catch {
//            assertOpenID4VPException(
//                error,
//                expectedMessage: "Given did url is not supported",
//                expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//    
//    func testThrowErrorWhenDidUrlMissingMethod() async {
//        let invalidDID = "did::123abc"
//        let didWebResolver = DidWebResolver(didUrl: invalidDID, networkManager: mockNetworkManager)
//        
//        do{
//            _ = try await didWebResolver.resolve()
//            XCTFail("Error - unsupportedDidUrl should be thrown but did not throw")
//        } catch {
//            assertOpenID4VPException(
//                error,
//                expectedMessage: "Given did url is not supported",
//                expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//    
//    func testThrowErrorDidResolutionFailedWhenAccessingDidDocumentViaNetworkCall() async {
//        let errorMessage = "Network Request failed with error response: response"
//        mockNetworkManager.setMockResponse(for: didDocumentUrl, error: NetworkRequestException.networkRequestFailed(message: errorMessage))
//        
//        let didWebResolver = DidWebResolver(didUrl: didUrl, networkManager: mockNetworkManager)
//        
//        do{
//            _ = try await didWebResolver.resolve()
//            XCTFail("Error - didResolutionFailed should be thrown but did not throw")
//        } catch {
//            assertOpenID4VPException(
//                error,
//                expectedMessage: "Network request failed with error response - Network Request failed with error response: response",
//                expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//        
//    }
//    
//    func testThrowErrorDidResolutionFailedWhenNetworkResponseToDidJsonIsInvalid() async {
//        let testCases: [TestCase<String, String>] = [
//            TestCase(input: "{\"key\":\"value", expectedError: "The data couldn’t be read because it isn’t in the correct format."),
//            TestCase(input: "\"Just a string\"", expectedError: "The data couldn’t be read because it isn’t in the correct format."),
//            TestCase(input: "Invalid JSON", expectedError: "The data couldn’t be read because it isn’t in the correct format."),
//            TestCase(input: "[1,2,3]", expectedError: "Conversion failed: resolved DID response is not a valid JSON object"),
//        ]
//        
//        for testCase in testCases {
//            mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: testCase.input)
//            
//            let didWebResolver = DidWebResolver(didUrl: didUrl, networkManager: mockNetworkManager)
//            
//            do {
//                _ = try await didWebResolver.resolve()
//                XCTFail("Error - DidResolutionFailed should have been thrown but did not throw")
//            } catch {
//               // let expectedMessage = "Failed to resolve did due to \(testCase.expectedError!)"
//                
//                // Check that error is OpenID4VPException subclass with correct message
//                assertOpenID4VPException(
//                    error,
//                    expectedMessage: testCase.expectedError!,
//                    expectedCode: OpenID4VPErrorCodes.invalidRequest
//                )
//            }
//        }
//    }
//
//}
