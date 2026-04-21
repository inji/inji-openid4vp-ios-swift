import XCTest
@testable import OpenID4VP

final class DCQLEvaluatorTests: XCTestCase {

    private let evaluator = DcqlEvaluator()

    private func dcqlQuery(_ json: String) throws -> DCQLQuery {
        try JSONDecoder().decode(DCQLQuery.self, from: Data(json.utf8))
    }

    // MARK: - Format matching

    func testReturnsSuccessWhenCredentialMatchesFormat() throws {
        
    }

    func testReturnsFailureWhenNoCredentialMatchesFormat() throws {
        
    }

    // MARK: - Cryptographic holder binding

    func testReturnsSuccessWhenHolderBindingRequired_AndCredentialSupportsIt() throws {
        
    }

    func testReturnsFailureWhenHolderBindingRequired_ButNoCredentialSupportsIt() throws {
        
    }

    func testReturnsSuccessWhenHolderBindingNotRequired_AndCredentialLacksIt() throws {
        
    }

    // MARK: - Meta filtering

    // Format : SD_JWT
    func testMetaFiltering_SdJwt_MatchingVct() throws {
        
    }
    
    func testMetaFiltering_EmptyMeta_PassesAllCredentials() throws {
        
    }

    func testMetaFiltering_SdJwt_NonMatchingVct() throws {

    }
    
    // Format: mso_mdoc

    func testMetaFiltering_Mdoc_MatchingDoctype() throws {
        
    }

    func testMetaFiltering_Mdoc_NonMatchingDoctype() throws {
    }
    
    // W3C credential - format: ldp_vc

    func testMetaFiltering_W3c_MatchingTypeValues() throws {
        
    }

    func testMetaFiltering_W3c_NonMatchingTypeValues() throws {
        
    }

    func testMetaFiltering_W3c_MatchesWhenAnyTypeValueOptionSatisfied() throws {
        
    }

    // MARK: - Claims matching
    
    // Format SD_JWT

    func testClaimsMatching_AllClaimsPresent() throws {
        
    }

    func testClaimsMatching_MissingClaimFails() throws {
        
    }

    func testClaimsMatching_NestedClaimPath() throws {
        
    }

    func testClaimsMatching_NoClaims_AllMandatoryClaimsShared() throws {
        
    }
    
    // Format: mso_mdoc

    func testClaimsMatching_MdocAllClaimsPresent() throws {
        
    }

    func testClaimsMatching_MdocMissingElementFails() throws {
        
    }

    // W3C Credential Format - ldp_vc

    func testClaimsMatching_W3cAllClaimsPresent() throws {
        
    }

    func testClaimsMatching_W3cMissingClaimFails() throws {
        
    }

    // MARK: - Value matching
    

    func testValueMatching_StringMatch() throws {
       
    }

    func testValueMatching_IntMatch() throws {
        
    }

    func testValueMatching_BoolMatch() throws {
        
    }

    func testValueMatching_NoMatchFails() throws {
        
    }

    // MARK: - claim_sets

    func testClaimSets_FirstOptionSatisfied() throws {
        
    }

    func testClaimSets_FallsBackToSecondOptionIfFirstOptionNotSatisfiable() throws {
        
    }

    func testClaimSets_NoOptionSatisfiedFails() throws {
        
    }

    // MARK: - multiple credentials

    func testMultipleFalse_ReturnsOnlyFirstMatchingCredential() throws {
        
    }

    func testMultipleTrue_ReturnsAllMatchingCredentials() throws {
        
    }

    // MARK: - Mdoc claim resolution

    func testMdocClaimResolution_MatchingNamespaceAndElement() throws {
        
    }

    func testMdocClaimResolution_MissingNamespaceFails() throws {
        
    }

    // MARK: - credential_sets

    func testCredentialSets_RequiredSetSatisfied() throws {
        
    }

    func testCredentialSets_RequiredSetNotSatisfiedFails() throws {
        
    }

    func testCredentialSets_OptionalSetNotSatisfiedStillSucceeds() throws {
        
    }

    func testCredentialSets_NoCredentialSets_AllQueriesMustBePresent() throws {
        
    }

    func testCredentialSets_NoCredentialSets_AllQueriesSatisfiedSucceeds() throws {
        
        
    }

    // MARK: - QueryEvaluationResult structure

    func testResultContainsCredentialSetRequirements() throws {
        
    }

    func testResultAllowMultipleCredentialsReflectsQueryFlag() throws {
        
    }

    func testEmptyWalletCredentials_ReturnsFailure() throws {
        
    }
}
