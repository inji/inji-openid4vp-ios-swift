import XCTest
@testable import OpenID4VP

final class DidWebResolverTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    
    let didUrl = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs"
    
    func testResolveDidUrlToDidDocumentSuccessfully() async {
        let didWebResolver = DidWebResolver(didUrl: didUrl, networkManager: mockNetworkManager)
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        
        let didDocument = try! await didWebResolver.resolve()
        
        assertDictionariesEqual(expected: [
            "assertionMethod": [
                "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
            ],
            "service": [],
            "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
            "verificationMethod": [
                [
                    "publicKey": "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=",
                    "controller": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
                    "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
                    "type": "Ed25519VerificationKey2020",
                    "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
                ]
            ],
            "@context": [
                "https://www.w3.org/ns/did/v1"
            ],
            "alsoKnownAs": [],
            "authentication": [
                "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
            ]
        ], actual: didDocument)
    }
    
    func testDIDWebWithParamsPathQuertAndFragmentSection() async throws {
        let testCases: [TestCase] = [
            TestCase(input: "did:web:example.com;param=", expectedError: ""),
            TestCase(input: "did:web:example.com;param=value", expectedError: ""),
            TestCase(input: "did:web:example.com;param=value/user/profile?verified=true#contact", expectedError: "")
        ]
        
        for testCase in testCases {
            mockNetworkManager.setMockResponse(for: URL(string: "https://example.com/did.json")!, responseBody: didResponse)
            let didWebResolver = DidWebResolver(didUrl: testCase.input, networkManager: mockNetworkManager)
            
            let didDocument = try await didWebResolver.resolve()
            
            assertDictionariesEqual(expected: [
                "assertionMethod": [
                    "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
                ],
                "service": [],
                "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
                "verificationMethod": [
                    [
                        "publicKey": "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=",
                        "controller": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
                        "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
                        "type": "Ed25519VerificationKey2020",
                        "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
                    ]
                ],
                "@context": [
                    "https://www.w3.org/ns/did/v1"
                ],
                "alsoKnownAs": [],
                "authentication": [
                    "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
                ]
            ], actual: didDocument)
        }
    }
    
    func testThrowErrorWhenDidUrlIsNonWebMethod() async {
        let invalidDID = "did:jwk:z6MkXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        let didWebResolver = DidWebResolver(didUrl: invalidDID, networkManager: mockNetworkManager)
        
        do{
            _ = try await didWebResolver.resolve()
            XCTFail("Error - unsupportedDidUrl should be thrown but did not throw")
        } catch {
            XCTAssertEqual(error as? DidResolverExceptions , DidResolverExceptions.unsupportedDidUrl(message: "Given did url is not supported"))
        }
    }
    
    func testThrowErrorWhenDidUrlIsEmptyString() async {
        let invalidDID = ""
        let didWebResolver = DidWebResolver(didUrl: invalidDID, networkManager: mockNetworkManager)
        
        do{
            _ = try await didWebResolver.resolve()
            XCTFail("Error - unsupportedDidUrl should be thrown but did not throw")
        } catch {
            XCTAssertEqual(error as? DidResolverExceptions , DidResolverExceptions.unsupportedDidUrl(message: "Given did url is not supported"))
        }
    }
    
    func testThrowErrorWhenDidUrlMissingMethod() async {
        let invalidDID = "did::123abc"
        let didWebResolver = DidWebResolver(didUrl: invalidDID, networkManager: mockNetworkManager)
        
        do{
            _ = try await didWebResolver.resolve()
            XCTFail("Error - unsupportedDidUrl should be thrown but did not throw")
        } catch {
            XCTAssertEqual(error as? DidResolverExceptions , DidResolverExceptions.unsupportedDidUrl(message: "Given did url is not supported"))
        }
    }
    
    func testThrowErrorDidResolutionFailedWhenAccessingDidDocumentViaNetworkCall() async {
        let errorMessage = "Network Request failed with error response: response"
        mockNetworkManager.setMockResponse(for: didDocumentUrl, error: NetworkRequestException.networkRequestFailed(message: errorMessage))
        
        let didWebResolver = DidWebResolver(didUrl: didUrl, networkManager: mockNetworkManager)
        
        do{
            _ = try await didWebResolver.resolve()
            XCTFail("Error - didResolutionFailed should be thrown but did not throw")
        } catch {
            XCTAssertEqual(error as? DidResolverExceptions , DidResolverExceptions.didResolutionFailed(message: "Network request failed with error response - Network Request failed with error response: response"))
        }
        
    }
    
    struct TestCase {
        let input: String
        let expectedError: String
    }
    
    func testThrowErrorDidResolutionFailedWhenNetworkResponseToDidJsonIsInvalid() async {
        let testCases: [TestCase] = [
            TestCase(input: "{\"key\":\"value", expectedError: "The data couldn’t be read because it isn’t in the correct format."),
            TestCase(input: "\"Just a string\"" , expectedError: "The data couldn’t be read because it isn’t in the correct format."),
            TestCase(input: "Invalid JSON" , expectedError: "The data couldn’t be read because it isn’t in the correct format."),
            TestCase(input: "[1,2,3]" , expectedError: "Conversion failed"),
        ]
        
        for testCase in testCases {
            mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: testCase.input)
            
            let didWebResolver = DidWebResolver(didUrl: didUrl, networkManager: mockNetworkManager)
            
            do{
                _ = try await didWebResolver.resolve()
                XCTFail("Error - didResolutionFailed should be thrown but did not throw")
            } catch {
                XCTAssertEqual(error as? DidResolverExceptions , DidResolverExceptions.didResolutionFailed(message: testCase.expectedError))
                XCTAssertEqual("Failed to resolve did due to \(testCase.expectedError)", error.localizedDescription, "input - \(testCase.input) failed")
            }
        }
    }
}
