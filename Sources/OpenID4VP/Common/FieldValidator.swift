import Foundation

func isNeitherNullNorEmpty(field: String) -> Bool {
    return field != "null" && !field.isEmpty
}
