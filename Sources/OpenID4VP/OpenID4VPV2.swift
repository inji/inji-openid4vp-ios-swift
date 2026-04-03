import Foundation

public class OpenID4VPV2 {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest!
    private var responseUri: String?
    private var authorizationResponseHandler: AuthorizationResponseHandler
    private let walletMetadata: WalletMetadataV2
    private var walletNonce: String = ""
    private let nonceProvider: NonceProvider

    private let className = String(describing: type(of: OpenID4VP.self))

    public init(traceabilityId: String, walletMetadata: WalletMetadataV2 = WalletMetadataV2()) {
        self.traceabilityId = traceabilityId
        networkManager = NetworkManager.shared
        authorizationResponseHandler = AuthorizationResponseHandler(networkManager: networkManager)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
        nonceProvider = NonceProvider()
        walletNonce = nonceProvider.generateNonce()
    }

    internal init(traceabilityId: String, networkManager: NetworkManaging? = nil, walletMetadata: WalletMetadataV2 = WalletMetadataV2(), nonceProvider: NonceProvider = NonceProvider(), authorizationResponseHandler: AuthorizationResponseHandler? = nil) {
        self.networkManager = networkManager ?? NetworkManager.shared
        self.nonceProvider = nonceProvider

        self.traceabilityId = traceabilityId
        self.authorizationResponseHandler = authorizationResponseHandler ?? AuthorizationResponseHandler(networkManager: networkManager ?? NetworkManager.shared)
        self.walletMetadata = walletMetadata
        OpenID4VPException.setTraceabilityId(className: String(describing: type(of: self)), traceabilityId: traceabilityId)
    }

    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }

    
}
