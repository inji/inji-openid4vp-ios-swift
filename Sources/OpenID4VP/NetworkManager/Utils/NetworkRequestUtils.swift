import Foundation
import UniformTypeIdentifiers

fileprivate let contentType = "Content-Type"

extension HTTPURLResponse {
    func isHeaderContentType(equalTo expectedvalue: String) -> Bool {
        let contentType = self.value(forHTTPHeaderField: contentType)
        let mediaType = contentType?.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: true).first?.trimmingCharacters(in: .whitespaces)
        return mediaType == expectedvalue
    }
}
