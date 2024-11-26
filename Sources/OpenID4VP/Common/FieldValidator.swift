import Foundation

func isNeitherNullNorEmpty(field: String) -> Bool {
    return field != "nil" && !field.isEmpty
}
