struct DescriptorMap: Encodable{
    let id: String
    let format: FormatType
    let path: String
}

struct PresentationSubmission: Encodable{
    let id: String = UUIDGenerator.generateUUID()
    let definition_id: String
    let descriptor_map: [DescriptorMap]
}
