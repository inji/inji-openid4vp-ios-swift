import Foundation

struct AuthorizationResponse {
    let vpToken: VPTokenType
    let presentation_submission: PresentationSubmission
    let state: String?
    static let className = String(describing: AuthorizationResponse.self)

    func toJsonEncodedMap() throws -> [String: String] {
        let encodedVPTokenData =  vpToken.encoded ?? ""
        let encodedPresentationSubmission = try encode(self.presentation_submission, fieldName: "presentation_submission")
        var bodyParams: [String: String] = [
            "vp_token": encodedVPTokenData,
            "presentation_submission": encodedPresentationSubmission
        ]
        
        if let state = state {
            bodyParams["state"] = state
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
    var encoded: String? {
        do {
            switch self {
            case .vpTokenArray(let tokens):
                let encodedTokens = try tokens.map { try encode($0, fieldName: "vpToken") }
                return try encode(encodedTokens, fieldName: "vpTokenArray")

            case .vpTokenElement(let token):
                let encodedToken = try encode(token, fieldName: "vpTokenElement")
                return encodedToken
            }
        } catch {
            return nil
        }
    }
}

