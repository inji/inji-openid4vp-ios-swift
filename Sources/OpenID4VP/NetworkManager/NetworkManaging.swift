import Foundation
import Alamofire

public protocol NetworkManaging {
    func sendHTTPRequest(url: String, method: HttpMethod, bodyParams: [String:Any]?, headers: [String: String]?) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse)
}
