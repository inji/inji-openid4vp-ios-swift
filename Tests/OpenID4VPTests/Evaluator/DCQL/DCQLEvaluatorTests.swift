import XCTest
@testable import OpenID4VP

final class DCQLEvaluatorTests: XCTestCase {

    private let evaluator = DcqlEvaluator()

    private func dcqlQuery(_ json: String) throws -> DCQLQuery {
        try JSONDecoder().decode(DCQLQuery.self, from: Data(json.utf8))
    }

    // MARK: - Format matching

    func testReturnsSuccessWhenCredentialMatchesFormat() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {} }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
        XCTAssertNotNil(result.queryMatches["cred1"]?.candidateCredentials)
    }

    func testReturnsFailureWhenNoCredentialMatchesFormat() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {} }] }
        """)
        let credential = MdocCredential(credentialId: "c1", credentialFormat: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL", namespaces: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertNil(result.queryMatches["cred1"]?.candidateCredentials)
        XCTAssertEqual(result.queryMatches["cred1"]?.failedClaims?.first?.reason, "No credentials found matching format for format : 'dc+sd-jwt'")
    }

    // MARK: - Cryptographic holder binding

    func testReturnsSuccessWhenHolderBindingRequired_AndCredentialSupportsIt() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {}, "require_cryptographic_holder_binding": true }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:], cryptographicHolderBinding: true)

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testReturnsFailureWhenHolderBindingRequired_ButNoCredentialSupportsIt() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {}, "require_cryptographic_holder_binding": true }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:], cryptographicHolderBinding: false)

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.failedClaims?.first?.reason, "No credential with cryptographic holder binding found for format 'dc+sd-jwt'")
    }

    func testReturnsSuccessWhenHolderBindingNotRequired_AndCredentialLacksIt() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {}, "require_cryptographic_holder_binding": false }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:], cryptographicHolderBinding: false)

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    // MARK: - Meta filtering

    // Format : SD_JWT
    func testMetaFiltering_SdJwt_MatchingVct() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": { "vct_values": ["https://example.com/identity"] } }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/identity", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }
    
    func testMetaFiltering_EmptyMeta_PassesAllCredentials() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {} }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/any", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testMetaFiltering_SdJwt_NonMatchingVct() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": { "vct_values": ["https://example.com/identity"] } }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/other", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.failedClaims?.first?.reason, "No credentials matched the meta constraints for format 'dc+sd-jwt'")
    }
    
    // Format: mso_mdoc

    func testMetaFiltering_Mdoc_MatchingDoctype() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }] }
        """)
        let credential = MdocCredential(credentialId: "c1", credentialFormat: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL", namespaces: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testMetaFiltering_Mdoc_NonMatchingDoctype() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }] }
        """)
        let credential = MdocCredential(credentialId: "c1", credentialFormat: "mso_mdoc", doctype: "org.iso.23220.photoid.1", namespaces: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.failedClaims?.first?.reason, "No credentials matched the meta constraints for format 'mso_mdoc'")
    }
    
    // W3C credential - format: ldp_vc

    func testMetaFiltering_W3c_MatchingTypeValues() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "ldp_vc", "meta": { "type_values": [["VerifiableCredential", "IDCardCredential"]] } }] }
        """)
        let credential = W3cCredential(credentialId: "c1", credentialFormat: "ldp_vc", type: ["VerifiableCredential", "IDCardCredential"], claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testMetaFiltering_W3c_NonMatchingTypeValues() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "ldp_vc", "meta": { "type_values": [["VerifiableCredential", "IDCardCredential"]] } }] }
        """)
        let credential = W3cCredential(credentialId: "c1", credentialFormat: "ldp_vc", type: ["VerifiableCredential", "UniversityDegreeCredential"], claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.failedClaims?.first?.reason, "No credentials matched the meta constraints for format 'ldp_vc'")
    }

    func testMetaFiltering_W3c_MatchesWhenAnyTypeValueOptionSatisfied() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "ldp_vc", "meta": { "type_values": [["IDCardCredential"], ["UniversityDegreeCredential"]] } }] }
        """)
        let credential = W3cCredential(credentialId: "c1", credentialFormat: "ldp_vc", type: ["VerifiableCredential", "UniversityDegreeCredential"], claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    // MARK: - Claims matching
    
    // Format SD_JWT

    func testClaimsMatching_AllClaimsPresent() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [
                    { "path": ["given_name"] },
                    { "path": ["family_name"] }
                ]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["given_name": "John", "family_name": "Doe"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.candidateCredentials?.first?.matchingClaimIndexes, [0, 1])
    }

    func testClaimsMatching_MissingClaimFails() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["given_name"] }, { "path": ["address"] }]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["given_name": "John"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.queryMatches["cred1"]?.failedClaims?.contains { $0.reason.contains("address") } ?? false)
    }

    func testClaimsMatching_NestedClaimPath() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["address", "street_address"] }]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["address": ["street_address": "42 Market St"]])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testClaimsMatching_NoClaims_AllMandatoryClaimsShared() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {} }] }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["given_name": "John"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.candidateCredentials?.first?.matchingClaimIndexes, [])
    }
    
    // Format: mso_mdoc

    func testClaimsMatching_MdocAllClaimsPresent() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [
                    { "path": ["org.iso.18013.5.1", "given_name"] },
                    { "path": ["org.iso.18013.5.1", "family_name"] }
                ]
            }]
        }
        """)
        let credential = MdocCredential(
            credentialId: "c1", credentialFormat: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL",
            namespaces: ["org.iso.18013.5.1": ["given_name": "John", "family_name": "Doe"]]
        )

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.candidateCredentials?.first?.matchingClaimIndexes, [0, 1])
    }

    func testClaimsMatching_MdocMissingElementFails() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [
                    { "path": ["org.iso.18013.5.1", "given_name"] },
                    { "path": ["org.iso.18013.5.1", "birth_date"] }
                ]
            }]
        }
        """)
        let credential = MdocCredential(
            credentialId: "c1", credentialFormat: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL",
            namespaces: ["org.iso.18013.5.1": ["given_name": "John"]]
        )

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.queryMatches["cred1"]?.failedClaims?.contains { $0.reason.contains("birth_date") } ?? false)
    }

    // W3C Credential Format - ldp_vc

    func testClaimsMatching_W3cAllClaimsPresent() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "ldp_vc", "meta": {},
                "claims": [
                    { "path": ["given_name"] },
                    { "path": ["family_name"] }
                ]
            }]
        }
        """)
        let credential = W3cCredential(
            credentialId: "c1", credentialFormat: "ldp_vc",
            type: ["VerifiableCredential"],
            claims: ["given_name": "John", "family_name": "Doe"]
        )

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.candidateCredentials?.first?.matchingClaimIndexes, [0, 1])
    }

    func testClaimsMatching_W3cMissingClaimFails() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "ldp_vc", "meta": {},
                "claims": [
                    { "path": ["given_name"] },
                    { "path": ["email"] }
                ]
            }]
        }
        """)
        let credential = W3cCredential(
            credentialId: "c1", credentialFormat: "ldp_vc",
            type: ["VerifiableCredential"],
            claims: ["given_name": "John"]
        )

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.queryMatches["cred1"]?.failedClaims?.contains { $0.reason.contains("email") } ?? false)
    }

    // MARK: - Value matching
    

    func testValueMatching_StringMatch() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["last_name"], "values": ["Doe"] }]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["last_name": "Doe"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testValueMatching_IntMatch() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["age"], "values": [30] }]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["age": 30])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testValueMatching_BoolMatch() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["is_verified"], "values": [true] }]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["is_verified": true])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testValueMatching_NoMatchFails() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [{ "path": ["last_name"], "values": ["Smith"] }]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["last_name": "Doe"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.queryMatches["cred1"]?.failedClaims?.contains { $0.reason.contains("last_name") } ?? false)
    }

    // MARK: - claim_sets

    func testClaimSets_FirstOptionSatisfied() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [
                    { "id": "a", "path": ["given_name"] },
                    { "id": "b", "path": ["family_name"] },
                    { "id": "c", "path": ["birth_date"] }
                ],
                "claim_sets": [["a", "b"], ["a", "c"]]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["given_name": "John", "family_name": "Doe"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.candidateCredentials?.first?.matchingClaimIndexes, [0, 1])
    }

    func testClaimSets_FallsBackToSecondOptionIfFirstOptionNotSatisfiable() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [
                    { "id": "a", "path": ["given_name"] },
                    { "id": "b", "path": ["family_name"] },
                    { "id": "c", "path": ["birth_date"] }
                ],
                "claim_sets": [["a", "b"], ["a", "c"]]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["given_name": "John", "birth_date": "1990-01-01"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.candidateCredentials?.first?.matchingClaimIndexes, [0, 2])
    }

    func testClaimSets_NoOptionSatisfiedFails() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "dc+sd-jwt", "meta": {},
                "claims": [
                    { "id": "a", "path": ["given_name"] },
                    { "id": "b", "path": ["family_name"] },
                    { "id": "c", "path": ["birth_date"] }
                ],
                "claim_sets": [["a", "b"], ["a", "c"]]
            }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: ["family_name": "Doe"])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.failedClaims?.first?.reason, "No claim_set option could be satisfied for query id: 'cred1'")
    }

    // MARK: - multiple credentials

    func testMultipleFalse_ReturnsOnlyFirstMatchingCredential() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {}, "multiple": false }] }
        """)
        let c1 = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])
        let c2 = SdJwtCredential(credentialId: "c2", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [c1, c2])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.allowMultipleCredentials, false)
    }

    func testMultipleTrue_ReturnsAllMatchingCredentials() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {}, "multiple": true }] }
        """)
        let c1 = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])
        let c2 = SdJwtCredential(credentialId: "c2", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [c1, c2])

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.queryMatches["cred1"]?.allowMultipleCredentials, true)
    }

    // MARK: - Mdoc claim resolution

    func testMdocClaimResolution_MatchingNamespaceAndElement() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        }
        """)
        let credential = MdocCredential(
            credentialId: "c1", credentialFormat: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL",
            namespaces: ["org.iso.18013.5.1": ["given_name": "John"]]
        )

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testMdocClaimResolution_MissingNamespaceFails() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{
                "id": "cred1", "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "given_name"] }]
            }]
        }
        """)
        let credential = MdocCredential(
            credentialId: "c1", credentialFormat: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL",
            namespaces: ["org.iso.7367.1": ["vehicle_holder": "John"]]
        )

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
    }

    // MARK: - credential_sets

    func testCredentialSets_RequiredSetSatisfied() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": {} },
                { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
            ],
            "credential_sets": [
                { "options": [["pid"], ["mdl"]], "required": true }
            ]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testCredentialSets_RequiredSetNotSatisfiedFails() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": {} },
                { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
            ],
            "credential_sets": [
                { "options": [["pid", "mdl"]], "required": true }
            ]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertFalse(result.success)
    }

    func testCredentialSets_OptionalSetNotSatisfiedStillSucceeds() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": {} },
                { "id": "bonus", "format": "dc+sd-jwt", "meta": { "vct_values": ["https://example.com/bonus"] } }
            ],
            "credential_sets": [
                { "options": [["pid"]], "required": true },
                { "options": [["bonus"]], "required": false }
            ]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertTrue(result.success)
    }

    func testCredentialSets_NoCredentialSets_AllQueriesMustBePresent() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": {} },
                { "id": "mdl", "format": "mso_mdoc", "meta": {} }
            ]
        }
        """)
        let pidCredential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [pidCredential])

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.credentialSets.isEmpty)
        XCTAssertNil(result.queryMatches["mdl"]?.candidateCredentials)
    }

    func testCredentialSets_NoCredentialSets_AllQueriesSatisfiedSucceeds() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": {} },
                { "id": "mdl", "format": "mso_mdoc", "meta": {} }
            ]
        }
        """)
        let pidCredential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])
        let mdlCredential = MdocCredential(credentialId: "c2", credentialFormat: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL", namespaces: [:])

        let result = evaluator.evaluate(query, inputCredentials: [pidCredential, mdlCredential])

        XCTAssertTrue(result.success)
        
    }

    // MARK: - QueryEvaluationResult structure

    func testResultContainsCredentialSetRequirements() throws {
        let query = try dcqlQuery("""
        {
            "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {} }],
            "credential_sets": [{ "options": [["cred1"]], "required": true }]
        }
        """)
        let credential = SdJwtCredential(credentialId: "c1", credentialFormat: "dc+sd-jwt", vct: "https://example.com/vct", claims: [:])

        let result = evaluator.evaluate(query, inputCredentials: [credential])

        XCTAssertEqual(result.credentialSets.count, 1)
        XCTAssertEqual(result.credentialSets.first?.options, [["cred1"]])
        XCTAssertTrue(result.credentialSets.first?.required ?? false)
    }

    func testResultAllowMultipleCredentialsReflectsQueryFlag() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {}, "multiple": true }] }
        """)

        let result = evaluator.evaluate(query, inputCredentials: [])

        XCTAssertTrue(result.queryMatches["cred1"]?.allowMultipleCredentials ?? false)
    }

    func testEmptyWalletCredentials_ReturnsFailure() throws {
        let query = try dcqlQuery("""
        { "credentials": [{ "id": "cred1", "format": "dc+sd-jwt", "meta": {} }] }
        """)

        let result = evaluator.evaluate(query, inputCredentials: [])

        XCTAssertFalse(result.success)
        XCTAssertNil(result.queryMatches["cred1"]?.candidateCredentials)
    }
}
