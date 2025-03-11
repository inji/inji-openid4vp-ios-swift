import Foundation

func constructBodyParams(vpToken: VPToken, presentationSubmission: PresentationSubmission, state: String?, shouldEncode: Bool = true) throws -> [String: Any] {
    var bodyParams: [String: Any] = [
        "vp_token": shouldEncode ? encodeQueryValue(try encode(vpToken, fieldName: "vp_token")) : vpToken,
        "presentation_submission": shouldEncode ? encodeQueryValue(try encode(presentationSubmission, fieldName: "presentation_submission")) : presentationSubmission
    ]
    
    if let state = state {
        bodyParams["state"] = shouldEncode ? encodeQueryValue(state) : state
    }
    
    return bodyParams
}
