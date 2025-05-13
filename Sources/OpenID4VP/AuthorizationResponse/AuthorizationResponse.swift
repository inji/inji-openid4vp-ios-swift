import Foundation

struct AuthorizationResponse {
    let vpToken: VPTokenType
    let presentation_submission: PresentationSubmission
    let state: String?
    static let className = String(describing: AuthorizationResponse.self)
    
    func toJsonEncodedMap() throws -> [String: Any] {
        var bodyParams : [String: Any] = [
            "vp_token": self.vpToken.encoded ?? [:],
            "presentation_submission": try self.presentation_submission.jsonData()
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
    var encoded: Any? {
        do {
            switch self {
            case .vpTokenArray(let tokens):
                let encodedTokens = try tokens.map { try $0.jsonData() }
                return encodedTokens
                
            case .vpTokenElement(let token):
                let encodedToken = try token.jsonData()
                return encodedToken
            }
        } catch {
            return nil
        }
    }
}

extension Encodable {
    func jsonData() throws -> Any {
        JSON.encoder.outputFormatting = [ .withoutEscapingSlashes]
        return try JSONSerialization.jsonObject(with: JSON.encoder.encode(self))
    }
}

struct JSON {
    // add pretty printed option
    static let encoder = JSONEncoder()
}
