public struct ProofJwtManager {
    let networkManager: NetworkManaging
    static let className = String(describing: ProofJwtManager.self)
    
    public func verifyJWT(jwtToken: String, clientId: String,  clienIdScheme: String) async throws {
        
        guard let handler = TypeHandlerFactory.getHandler(for: clienIdScheme) else {
            throw Logger.handleException(exceptionType: "InvalidClientIdScheme",message: "Client id scheme in request is invalid" ,className: ProofJwtManager.className)
        }
        try await handler.verify(jwtToken: jwtToken, clientId: clientId , networkManager: networkManager)
    }
}
