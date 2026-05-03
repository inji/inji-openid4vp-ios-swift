import Foundation

public struct DeviceAuthentication {
    let signature: Data
    let algorithm: String
    static let className = String(describing: DeviceAuthentication.self)
    
    public init(signature: Data, algorithm: String) {
        self.signature = signature
        self.algorithm = algorithm
    }
    
    func validate() throws {
        try validateField(field: self.signature, fieldPath: ["DeviceAuthentication","signature"], className: DeviceAuthentication.className)
        try validateField(field: self.algorithm, fieldPath: ["DeviceAuthentication","algorithm"], className: DeviceAuthentication.className)
    }
    
}
