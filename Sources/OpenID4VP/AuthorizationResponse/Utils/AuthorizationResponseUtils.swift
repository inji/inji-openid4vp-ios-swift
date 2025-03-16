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

func encodeVPTokenForSigning(_ vpTokensForSigning: [FormatType: VPTokenForSigning]) throws -> [String : String] {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .withoutEscapingSlashes
    var formatted: [String: String] = [:]
    for (key,value) in vpTokensForSigning {
        let encodedContent = try encoder.encode(value)
        formatted[key.rawValue] = String(data: encodedContent, encoding: .utf8)
    }

    return formatted

}
