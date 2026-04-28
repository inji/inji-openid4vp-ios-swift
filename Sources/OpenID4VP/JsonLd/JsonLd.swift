import Foundation

class JsonLd {
    static var canonicalizer: JsonLdCanonicalizerCallback? = nil
    
    static func setCanonicalizer(_ callback: JsonLdCanonicalizerCallback?) {
        JsonLd.canonicalizer = callback
    }
}
