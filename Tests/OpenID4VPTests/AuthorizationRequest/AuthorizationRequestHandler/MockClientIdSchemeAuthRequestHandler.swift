import Foundation
import XCTest
@testable import OpenID4VP

class MockClientIdSchemeAuthRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler {
    private let isRequestUriSupportedFlag: Bool
    private let isRequestObjectSupportedFlag: Bool
    
    
    init(authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata? = nil,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging,
         isRequestUriSupported: Bool = true,
         isRequestObjectSupported: Bool = true) {
        self.isRequestUriSupportedFlag = isRequestUriSupported
        self.isRequestObjectSupportedFlag = isRequestObjectSupported
        
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: Self.self)
    }
    
    func isRequestObjectSupported() -> Bool {
        return self.isRequestObjectSupportedFlag
    }
    
    func isRequestUriSupported() -> Bool {
        return self.isRequestUriSupportedFlag
    }
    
    func getHeadersForAuthorizationRequestUri() -> [String : String]? {
        return ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue,
                "accept": ContentTypes.applicationJson.rawValue]
    }
    
    func validateRequestUriResponse(requestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)?,walletNonce: String, isMismatchedAcceptableType: Bool) async throws {
        capturedRequestUriResponse = requestUriResponse
        wasMethodCalled = true
    }
    
    func process(walletMetadata: WalletMetadata) -> WalletMetadata {
        return walletMetadata
    }
    var capturedRequestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)?
    var wasMethodCalled = false
}
