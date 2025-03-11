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

