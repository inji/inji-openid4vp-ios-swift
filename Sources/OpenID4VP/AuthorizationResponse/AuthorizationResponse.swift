import Foundation

struct AuthorizationResponse {
    let vpToken: VPTokenType
    let presentation_submission: PresentationSubmission
    let state: String?
    static let className = String(describing: AuthorizationResponse.self)

    func toJsonEncodedMap(shouldEncode : Bool = true) throws -> [String: String] {
        let encodedVPTokenData =  String(data: vpToken.encoded!, encoding: .utf8) ?? ""
        let encodedPresentationSubmission = try encode(self.presentation_submission, fieldName: "presentation_submission")
        var bodyParams: [String: String] = [
            "vp_token": shouldEncode ? encodeQueryValue(encodedVPTokenData) : encodedVPTokenData,
            "presentation_submission": shouldEncode ? encodeQueryValue(encodedPresentationSubmission) : encodedPresentationSubmission
        ]
        
        if let state = state {
            bodyParams["state"] = shouldEncode ? encodeQueryValue(state) : state
        }
        
        return bodyParams
    }
}

public enum VPTokenType {
    case vpTokenArray([VPToken])
    case vpTokenElement(VPToken)

    enum CodingKeys: String, CodingKey {
        case type
        case value
    }
}

extension VPTokenType {
    var encoded: Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted

        switch self {
        case .vpTokenArray(let tokens):
            return try? encoder.encode(tokens.map{
                try encoder.encode($0)
            })

        case .vpTokenElement(let token):
            return try? encoder.encode(token)
        }
    }
}
