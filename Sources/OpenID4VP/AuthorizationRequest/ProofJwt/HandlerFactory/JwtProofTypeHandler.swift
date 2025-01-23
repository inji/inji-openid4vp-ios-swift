protocol JwtProofTypeHandler {
    func verify(jwtToken: String, clientId: String, networkManager: NetworkManaging) async throws
}
