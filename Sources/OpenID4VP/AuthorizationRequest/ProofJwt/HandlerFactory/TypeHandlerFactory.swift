struct TypeHandlerFactory {
    static func getHandler(for clientIdScheme: String) -> JwtProofTypeHandler? {
        if clientIdScheme == ClientIdScheme.did.rawValue {
            return DidHandler()
        }
        return nil
    }
}
