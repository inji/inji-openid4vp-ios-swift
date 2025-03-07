import Foundation

func createAuthorizationResponseBody(
    vpToken: VPToken,
    authorizationRequest: AuthorizationRequest,
    presentationSubmission: PresentationSubmission,
    state: String?
) throws -> [String: String] {
    
    let bodyParams = try constructBodyParams(
           vpToken: vpToken,
           presentationSubmission: presentationSubmission,
           state: state,
           responseMode: authorizationRequest.responseMode!
       )
    
    switch authorizationRequest.responseMode {
    case ResponseMode.directPost.rawValue:
        return bodyParams as! [String: String]
        
    case ResponseMode.directPostJwt.rawValue:
        let clientMetadata = (authorizationRequest.clientMetadata)!
        let encryptedBody = try JWEProcessor(clientMetadata: clientMetadata).createResponse(bodyParams: bodyParams)
        return ["response": encryptedBody]
    default:
        throw Logger.handleException(
            exceptionType: "InvalidResponseMode",
            message: "Given response_mode is not supported",
            className: AuthorizationResponse.className
        )
    }
}

func constructBodyParams(vpToken: VPToken, presentationSubmission: PresentationSubmission, state: String?, responseMode: String) throws -> [String: Any] {
    let shouldEncode = (responseMode == ResponseMode.directPost.rawValue)

    var bodyParams: [String: Any] = [
        "vp_token": shouldEncode ? encodeQueryValue(try encode(vpToken, fieldName: "vp_token")) : vpToken,
        "presentation_submission": shouldEncode ? encodeQueryValue(try encode(presentationSubmission, fieldName: "presentation_submission")) : presentationSubmission
    ]
    
    if let state = state {
        bodyParams["state"] = shouldEncode ? encodeQueryValue(state) : state
    }
    
    return bodyParams
}


func createDescriptorMap(verifiableCredentials: [String: [String]]) -> [DescriptorMap] {
    var pathIndex = 0
    var descriptorMap: [DescriptorMap] = []
    
    let sortedKeys = verifiableCredentials.keys.sorted()
    
    for key in sortedKeys {
        if let vcs = verifiableCredentials[key] {
            for _ in vcs {
                descriptorMap.append(
                    DescriptorMap(
                        id: key,
                        format: .ldp_vp,
                        path: "$.verifiableCredential[\(pathIndex)]"
                    )
                )
                pathIndex += 1
            }
        }
    }
    return descriptorMap
}

