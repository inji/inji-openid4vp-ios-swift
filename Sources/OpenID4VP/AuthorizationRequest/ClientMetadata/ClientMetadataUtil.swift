import Foundation

let className = String(describing: ClientMetadata.self)

func parseAndValidateClientMetadata(_ authorizationRequest: [String: Any],
                                    _ shouldValidateWithWalletMetadata: Bool,
                                    _ walletMetadata: WalletMetadata?) throws -> [String: Any] {
    var mutableParams = authorizationRequest
    if let clientMetadataObject = authorizationRequest["client_metadata"] as? NSDictionary{
        let data = try JSONSerialization.data(withJSONObject: clientMetadataObject, options: [])
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: data)
        mutableParams["client_metadata"] = clientMetadata
    } else if let clientMetaString = authorizationRequest["client_metadata"] as? String {
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetaString)
        mutableParams["client_metadata"] = clientMetadata
    }
    
    let responseMode = authorizationRequest[AuthorizationRequestFieldConstants.responseMode.rawValue] as? String
    try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).validate(clientMetadata: (mutableParams["client_metadata"] as! ClientMetadata),
                                                                                 walletMetadata: walletMetadata,
                                                                                 shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata)
    
    return mutableParams
}
