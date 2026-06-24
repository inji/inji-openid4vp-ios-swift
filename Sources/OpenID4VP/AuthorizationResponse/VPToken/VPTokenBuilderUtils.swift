import Foundation

func getVPTokenSigningResult(
    vpTokenSigningResults: [VPTokenSigningResult],
    identifier: String?,
    className: String
) throws -> VPTokenSigningResult {
    let matchingSigningResults = vpTokenSigningResults.filter { $0.id == identifier }
    guard matchingSigningResults.count == 1 else {
        throw MissingInput(
            fieldPath: "",
            message: "Missing VP token signing result for credential identifier \(identifier ?? "nil")",
            className: className
        )
    }
    return matchingSigningResults[0]
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
