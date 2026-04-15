public enum AuthorizationRequestFieldConstants: String {
    case clientId = "client_id"
    
    case responseType = "response_type"
    case responseMode = "response_mode"
    
    case presentationDefinition = "presentation_definition"
    case presentationDefinitionUri = "presentation_definition_uri"
    case dcqlQuery = "dcql_query"
    
    case responseUri = "response_uri"
    case redirectUri = "redirect_uri"
    
    case requestUri = "request_uri"
    case request = "request"
    case requestUriMethod = "request_uri_method"
    
    case nonce = "nonce"
    case walletNonce = "wallet_nonce"
    case state = "state"
    
    case clientMetadata = "client_metadata"
    
    case transactionData = "transaction_data"
}
