import Foundation

//TODO: Check if builder has to be kept in root or types folder
protocol UnsignedVPTokenBuilder {
    func build() throws -> UnsignedVPToken
}
