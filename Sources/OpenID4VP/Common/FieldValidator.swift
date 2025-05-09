import Foundation

func isNeitherNullNorEmpty(field: String) -> Bool {
    return field != "nil" && !field.isEmpty
}

func isValidString(_ field: String) -> Bool {
    return field != "nil" && !field.isEmpty && field != "null"
}

func validateField<T>(field: T, fieldPath: [String], className: String) throws {
    switch field {
    case let stringValue as String:
        if !isValidString(stringValue) {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: fieldPath,
                className: className
            )
        }
    default:
        break
    }
}
