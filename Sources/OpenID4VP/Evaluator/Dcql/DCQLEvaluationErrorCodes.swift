public enum DCQLEvaluationErrorCodes : String {
    case noMatchingFormatsFound = "no_matching_credentials_with_requested_credential_formats_found"
    case cryptograhicHolderbindingOrMetaFilterMismatch = "cryptographic_holderbinding_or_meta_filter_mismatch"
    case noClaimsSetOptionSatisfied = "no_claims_set_option_satisfied"
    
    case claimUnavailable = "CLAIM_UNAVAILABLE"
    case claimValueMismatch = "CLAIM_VALUE_NOT_MATCHING"
}
