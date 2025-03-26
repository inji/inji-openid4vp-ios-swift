import Foundation

func parseAndValidatePresentationDefinition(
    authorizationRequest: [String: Any],
    networkManager: NetworkManaging
) async throws -> [String: Any] {
    
    let hasPresentationDefinition = authorizationRequest.keys.contains("presentation_definition")
    let hasPresentationDefinitionUri = authorizationRequest.keys.contains("presentation_definition_uri")
    var finalPresentationDefinition: PresentationDefinition
    
    guard hasPresentationDefinition != hasPresentationDefinitionUri else {
        throw Logger.handleException(
            exceptionType: "InvalidData",
            message: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
            className: AuthorizationRequest.className
        )
    }
    
    
    if hasPresentationDefinition, let value = authorizationRequest["presentation_definition"] {
        if let presentationDefinitionString = value as? String {
            //Presentation Definition is of type String when auth request obtained by value
            guard let valueStr = getStringValue(presentationDefinitionString), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
                throw Logger.handleException(
                    exceptionType: "InvalidInput",
                    fieldPath: ["presentation_definition"],
                    className: AuthorizationRequest.className
                )
            }

            finalPresentationDefinition = try convertToInstance(valueStr, as: PresentationDefinition.self, fieldPath: [AuthorizationRequestFieldConstants.presentationDefinition.rawValue], className: PresentationDefinition.className)
        } else if let presentationDefinitionJson = value as? [String: Any] {
            //Presentation Definition is of type Dictionary when auth request obtained by reference
            do {
                finalPresentationDefinition = try convertToInstance(presentationDefinitionJson, as: PresentationDefinition.self)
            } catch {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "presentation_defintion data is not valid",
                    className: AuthorizationRequest.className
                )
            }
        } else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "presentation_defintion data is not valid",
                className: AuthorizationRequest.className
            )
        }
    } else if hasPresentationDefinitionUri, let presentationDefintionUri = authorizationRequest[AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue] {
        guard let valueStr = getStringValue(presentationDefintionUri), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: [AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue],
                className: AuthorizationRequest.className
            )
        }
        guard isValidUri(presentationDefintionUri as! String)
        else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "presentation_defintion_uri data is not valid",
                className: AuthorizationRequest.className
            )
        }
        
        let response = try await networkManager.sendHTTPRequest(
            url: valueStr, method: .get, bodyParams: nil, headers: nil
        )
        guard let data = response.responseBody.data(using: .utf8) else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "presentation_defintion_uri data is not valid",
                className: AuthorizationRequest.className
            )
        }
        
        finalPresentationDefinition = try data.toInstance(as: PresentationDefinition.self)
        
    } else {
        throw Logger.handleException(
            exceptionType: "InvalidData",
            message: "Either presentation_definition or presentation_definition_uri request param must be present",
            className: AuthorizationRequest.className
        )
    }
    
    var mutableParams = authorizationRequest
    mutableParams[AuthorizationRequestFieldConstants.presentationDefinition.rawValue] = finalPresentationDefinition
    
    return mutableParams
}
