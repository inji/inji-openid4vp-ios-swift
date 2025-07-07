import Foundation

class OpenID4VPException: Error, CustomStringConvertible, LocalizedError {
    let errorCode: String
    let message: String
    let className: String

    init(errorCode: String, message: String, className: String) {
        self.errorCode = errorCode
        self.message = message
        self.className = className
        print("ERROR [\(errorCode)] - \(message) | Class: \(className)")
    }

    var description: String {
        return "\(errorCode) : \(message)"
    }

    var errorDescription: String? {
        return message
    }

    func toErrorResponse() -> [String: String] {
        return [
            "error": errorCode,
            "error_description": message
        ]
    }
}


class InvalidQueryParams: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

// MARK: - Specific Exceptions

class InvalidVerifier: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class InvalidInputPattern: OpenID4VPException {
    init(fieldPath: Any, className: String) {
        let pattern = (fieldPath as? [String])?.joined(separator: "->") ?? "\(fieldPath)"
        let message = "Invalid Input Pattern: \(pattern) pattern is not matching with OpenId4VP specification"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class JsonEncodingFailed: OpenID4VPException {
    init(fieldPath: Any? = nil, errorMessage: String, className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: "Json encoding failed for \(fieldPath ?? "") due to this error: \(errorMessage)",
            className: className
        )
    }
}

class DeserializationFailure: OpenID4VPException {
    init(fieldPath: Any, errorMessage: String, className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: "Deserializing for \(fieldPath) failed due to this error: \(errorMessage)",
            className: className
        )
    }
}

class InvalidLimitDisclosure: OpenID4VPException {
    init(className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: "Invalid Input: constraints->limit_disclosure value should be preferred",
            className: className
        )
    }
}



class InvalidData: OpenID4VPException {
    init(message: String, className: String, code: String? = nil) {
        super.init(errorCode: code ?? OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class MissingInput: OpenID4VPException {
    init(fieldPath: Any, message: String? = "", className: String) {
        let resolvedMessage: String
        if let field = fieldPath as? String, !field.isEmpty {
            resolvedMessage = "Missing Input: \(field) param is required"
        } else if let list = fieldPath as? [String], !list.isEmpty {
            resolvedMessage = "Missing Input: \(list.joined(separator: "->")) param is required"
        } else {
            resolvedMessage = message ?? ""
        }
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: resolvedMessage, className: className)
    }
}

class InvalidInput: OpenID4VPException {
    init(fieldPath: Any, value: Any? = nil, className: String) {
        let path = (fieldPath as? [String])?.joined(separator: "->") ?? "\(fieldPath)"
        let message: String

        if let str = value as? String, str.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            message = "Invalid Input: \(path) value cannot be empty or null"
        } else if value == nil {
            message = "Invalid Input: \(path) value cannot be empty or null"
        } else if let boolVal = value as? Bool {
            message = "Invalid Input: \(path) value must be either true or false"
        } else {
            message = "Invalid Input: \(path) value is invalid"
        }

        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}



// MARK: - JWS

class PublicKeyExtractionFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class KidExtractionFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class PublicKeyResolutionFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class InvalidSignature: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class VerificationFailure: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class JsonDecodingFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: message,
            className: className
        )
    }
}


// MARK: - JWE


class UnsupportedEncryptionAlgorithm: OpenID4VPException {
    init(className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: "Required Encryption algorithm is not supported", className: className)
    }
}



class UnsupportedKeyExchangeAlgorithm: OpenID4VPException {
    init(className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: "Required Key exchange algorithm is not supported", className: className)
    }
}

class JweEncryptionFailure: OpenID4VPException {
    init(className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: "JWE Encryption failed", className: className)
    }
}

class UnsupportedDidUrl: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class DidResolutionFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class PayloadConversionFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class InvalidResponseMode: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class GenericFailure: OpenID4VPException {
    init(message: String = "", className: String) {
        let message = "Unknown error occurred \(message)"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}




class InvalidType: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class MismatchingClientIDInRequest: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class MismatchingClientIdSchemeInRequest: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class UnsupportedKeyAgreementAlgorithm: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class PublicKeyConversionFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class InvalidEncryptionKeySize: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class UnsupportedHttpMethod: OpenID4VPException {
    init(message: String, className: String) {
        let message = "Unsupported HTTP method: \(message)"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class UnsupportedSignatureAlgorithm: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class Base64DecodingFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}



class UTF8EncodingFailed: OpenID4VPException {
    init(fieldPath: Any, className: String) {
        let message = "Failed to convert \(fieldPath) string to UTF-8 data"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}






