import Foundation

func getVPTokenSigningResult(
    vpTokenSigningResults: [VPTokenSigningResult],
    identifier: String?,
    className: String
) throws -> VPTokenSigningResult {
    guard let identifier = identifier else {
        throw InvalidData(
            message: "Missing identifier",
            className: className
        )
    }
    let matchingSigningResults = vpTokenSigningResults.filter { $0.id == identifier }
    guard matchingSigningResults.count == 1 else {
        throw MissingInput(
            fieldPath: "",
            message: "Missing VP token signing result for credential identifier \(identifier)",
            className: className
        )
    }
    
    let vpTokenSigningResult = matchingSigningResults[0]
    
    guard !vpTokenSigningResult.signedData.isEmpty else {
        throw MissingInput(fieldPath: "", message: "Invalid signature for identifier \(identifier)", className: className)
    }
    
    return vpTokenSigningResult
}

func getUnsignedVPToken(
    unsignedVPTokens: [UnsignedVPToken],
    identifier: String,
    className: String
) throws -> UnsignedVPToken {
    let matchingUnsignedVPTokens = unsignedVPTokens.filter { $0.id == identifier }
    guard matchingUnsignedVPTokens.count == 1 else {
        throw InvalidData(
            message: "Missing unsigned VP token for id: \(identifier)",
            className: className
        )
    }
    return matchingUnsignedVPTokens[0]
}
