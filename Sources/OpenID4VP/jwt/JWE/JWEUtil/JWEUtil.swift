import Foundation

func toData(_ bodyParams: [String: Any]) throws -> Data {
    var processedParams: [String: Any] = [:]

    for (key, value) in bodyParams {
        if let encodableValue = value as? Encodable {
            if let converted = encodableValue.toDictionary() {
                processedParams[key] = converted
            } else {
                processedParams[key] = value
            }
        } else {
            processedParams[key] = value
        }
    }
    return try JSONSerialization.data(withJSONObject: processedParams, options: [])
}
