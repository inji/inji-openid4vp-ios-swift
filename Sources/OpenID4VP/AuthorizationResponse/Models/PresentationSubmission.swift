struct DescriptorMap: Encodable{
    let id: String
    let format: VPFormatType
    let path: String
    let pathNested: PathNested?
    
    enum CodingKeys: String, CodingKey {
        case id
        case format
        case path
        case pathNested = "path_nested"
    }
}

struct PathNested : Encodable {
    let id: String
    let format: FormatType
    let path: String
}

//TODO: use coding keys to handle modification of field names
struct PresentationSubmission: Encodable{
    let id: String = UUIDGenerator.generateUUID()
    let definition_id: String
    let descriptor_map: [DescriptorMap]
}
