import Foundation

fileprivate let className = String(describing: ClientMetadataSpecVersionDraft23.self)

enum ClientMetadataVersionLogic {
    case v1, draft23
    
    static func of(_ specVersion: SpecVersion) -> ClientMetadataVersionLogic {
        return specVersion == .draft23 ? .draft23 : .v1
    }
    
    func parseAndValidate(authorizationRequest: [String: Any], shouldValidateWithWalletMetadata: Bool, walletMetadata: WalletMetadata?) throws -> [String: Any] {
        let clientMetadataKey = AuthorizationRequestFieldConstants.clientMetadata.rawValue
        var mutableParams = authorizationRequest
        if let clientMetadata = authorizationRequest[AuthorizationRequestFieldConstants.clientMetadata.rawValue] {
            switch self {
            case .draft23:
                if let clientMetadataInstance = clientMetadata as? ClientMetadataSpecVersionDraft23 {
                    mutableParams[clientMetadataKey] = clientMetadataInstance
                }
                else if let clientMetadataObject = clientMetadata as? NSDictionary{
                    let data = try JSONSerialization.data(withJSONObject: clientMetadataObject, options: [])
                    let clientMetadata = try ClientMetadataSpecVersionDraft23.deserializeAndValidate(clientMetadata: data)
                    mutableParams[clientMetadataKey] = clientMetadata
                } else if let clientMetaString = clientMetadata as? String {
                    let clientMetadata = try ClientMetadataSpecVersionDraft23.deserializeAndValidate(clientMetadata: clientMetaString)
                    mutableParams[clientMetadataKey] = clientMetadata
                } else {
                    throw InvalidData(message: "client_metadata must be of type String or Map", className: className)
                }
            case .v1:
                if let clientMetadataInstance = clientMetadata as? ClientMetadataSpecVersion1 {
                    mutableParams[clientMetadataKey] = clientMetadataInstance
                }
                else if let clientMetadataObject = clientMetadata as? NSDictionary{
                    let data = try JSONSerialization.data(withJSONObject: clientMetadataObject, options: [])
                    let clientMetadata = try ClientMetadataSpecVersion1.deserializeAndValidate(clientMetadata: data)
                    mutableParams[clientMetadataKey] = clientMetadata
                } else if let clientMetaString = clientMetadata as? String {
                    let clientMetadata = try ClientMetadataSpecVersion1.deserializeAndValidate(clientMetadata: clientMetaString)
                    mutableParams[clientMetadataKey] = clientMetadata
                } else {
                    throw InvalidData(message: "client_metadata must be of type String or Map", className: className)
                }
            }
        }
        
        let responseMode = authorizationRequest[AuthorizationRequestFieldConstants.responseMode.rawValue] as? String
        let parsedClientMetadata = mutableParams[clientMetadataKey]
        switch self {
        case .v1:
            try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).validate(
                clientMetadata: (parsedClientMetadata as? ClientMetadataSpecVersion1),
                walletMetadata: walletMetadata,
                shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata
            )
        case .draft23:
            try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).validate(
                clientMetadata: (parsedClientMetadata as? ClientMetadataSpecVersionDraft23),
                walletMetadata: walletMetadata,
                shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata
            )
        }
        
        return mutableParams
    }
        
}
