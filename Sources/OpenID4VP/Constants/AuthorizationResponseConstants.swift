import Foundation

public enum FormatType: String, Codable {
    case ldp_vc = "ldp_vc"
    case mso_mdoc = "mso_mdoc"
}

public enum VPFormatType: String, Codable {
    case ldp_vp = "ldp_vp"
    case mso_mdoc = "mso_mdoc"
}

public enum ProofPurpose: String, Codable {
    case vpProofPurpose = "authentication"
}
