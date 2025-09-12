import Foundation

protocol UnsignedVPTokenBuilder {
    func build() async throws -> [String:Any]
}
