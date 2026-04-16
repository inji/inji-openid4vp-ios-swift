
internal struct DcqlEvaluator {
    internal func evaluate(_ dcqlQuery: DCQLQuery, inputCredentials: [any ProcessedCredential]) -> QueryEvaluationResult {
        var queryMatches: [String: QueryMatchResult] = [:]
        
        for credentialQuery in dcqlQuery.credentials {
            queryMatches[credentialQuery.id] = evaluateCredentialQuery(credentialQuery, against: inputCredentials)
        }
        
        let credentialSetRequirements = buildCredentialSetRequirements(dcqlQuery: dcqlQuery)
        let success = isQuerySatisfied(queryMatches: queryMatches, credentialSets: credentialSetRequirements, dcqlQuery: dcqlQuery)
        
        return QueryEvaluationResult(success: success, queryMatches: queryMatches, credentialSets: credentialSetRequirements)
    }
    
    private func evaluateCredentialQuery(_ credentialQuery: CredentialQuery, against walletCredentials: [any ProcessedCredential]) -> QueryMatchResult {
        var filteredWalletCredentials: [any ProcessedCredential] = []
        
        // 1. Find all macthing credentials as per format
        let filteredFormatMatchingWalletCredentials = walletCredentials.filter { $0.credentialFormat == credentialQuery.format }
        
        if filteredFormatMatchingWalletCredentials.isEmpty {
            return QueryMatchResult(
                failedClaims: [ClaimFailure(claimIndex: -1, reason: "No credentials found matching format for format : '\(credentialQuery.format)'")],
                allowMultipleCredentials: credentialQuery.multiple
            )
        }
        
        filteredWalletCredentials = filteredFormatMatchingWalletCredentials
        
        // 2. Filter the format level matching credentials based on cryptographic holder binding requirement
        if credentialQuery.requireCryptographicHolderBinding {
            let holderBindingCapableWalletCredentials = filteredFormatMatchingWalletCredentials.filter { $0.cryptographicHolderBinding }
            if holderBindingCapableWalletCredentials.isEmpty {
                return QueryMatchResult(
                    failedClaims: [ClaimFailure(claimIndex: -1, reason: "No credential with cryptographic holder binding found for format '\(credentialQuery.format)'")],
                    allowMultipleCredentials: credentialQuery.multiple
                )
            }
            filteredWalletCredentials = holderBindingCapableWalletCredentials
        }
        
        // 3.Apply the meta filtering on top of the format and cryptographic holder binding filtered credentials
        if !credentialQuery.meta.isEmpty {
            filteredWalletCredentials = filteredWalletCredentials.filter { matchesMeta(credentialQuery.meta, walletCredential: $0) }
            if filteredWalletCredentials.isEmpty {
                return QueryMatchResult(
                    failedClaims: [ClaimFailure(claimIndex: -1, reason: "No credentials matched the meta constraints for format '\(credentialQuery.format)'")],
                    allowMultipleCredentials: credentialQuery.multiple
                )
            }
        }
        
        
        // 4. Apply the claims level check
        var candidateCredentials: [CandidateCredential] = []
        var failedClaims: [ClaimFailure] = []
        
        for walletCredential in filteredWalletCredentials {
            let (matchingClaimIndexes, claimFailures) = evaluateClaims(credentialQuery: credentialQuery, walletCredential: walletCredential)
            
            if claimFailures.isEmpty {
                candidateCredentials.append(CandidateCredential(credentialId: walletCredential.credentialId, matchingClaimIndexes: matchingClaimIndexes))
            } else {
                // Failed claims holds the reason for claims check failure which deos not include any details about credential
                failedClaims.append(contentsOf: claimFailures)
            }
        }
        
        if candidateCredentials.isEmpty {
            return QueryMatchResult(failedClaims: failedClaims.isEmpty ? nil : failedClaims, allowMultipleCredentials: credentialQuery.multiple)
        }
        
        return QueryMatchResult(candidateCredentials: candidateCredentials, allowMultipleCredentials: credentialQuery.multiple)
    }
    
    // Evaluates claims and claim_sets
    private func evaluateClaims(credentialQuery: CredentialQuery, walletCredential: any ProcessedCredential) -> (matchingClaimIndexes: [Int], failedClaims: [ClaimFailure]) {
        // If no claims is available in VP request, all mandatory claims of the credential needs to be shared to Verifier
        guard let claims = credentialQuery.claims else {
            return ([], [])
        }
        
        // One of the options of the claim_sets needs to be satisfied if claim_sets is present in the VP request.
        
        if let claimSets = credentialQuery.claimSets {
            // claim_sets are ordered by preference, so we iterate through the options and return as soon as we find a satisfied option
            for claimSetOption in claimSets {
                //TODO: If claim set is there claim id is mandatory add hat check instead of fallback to ""
                let requestedClaims = claims.enumerated().filter { claimSetOption.contains($0.element.id ?? "") }
                let (matchingClaimIndexes, failedClaims) = checkClaims(requestedClaims.map { ($0.offset, $0.element) }, walletCredential: walletCredential)
                
                // Once the claim_set option with all claims satisfied is found, return the result without evaluating further options as claim_sets are in order of preference
                if failedClaims.isEmpty {
                    return (matchingClaimIndexes, [])
                }
            }
            return ([], [ClaimFailure(claimIndex: -1, reason: "No claim_set option could be satisfied for query id: '\(credentialQuery.id)'")])
        }
        
        // If claim_sets is not present, then all claims in the VP request need to be satisfied
        let requestedClaims = claims.enumerated().map { ($0.offset, $0.element) }
        return checkClaims(requestedClaims, walletCredential: walletCredential)
    }
    
    private func checkClaims(_ indexedClaims: [(Int, ClaimsQuery)], walletCredential: any ProcessedCredential) -> (matchingClaimIndexes: [Int], failedClaims: [ClaimFailure]) {
        var matchingClaimIndexes: [Int] = []
        var failedClaims: [ClaimFailure] = []
        
        for (index, claimQuery) in indexedClaims {
            let pathStrings = claimQuery.path.compactMap { $0.value as? String }
            
            guard let claimValue = resolveClaimValue(path: pathStrings, credential: walletCredential) else {
                failedClaims.append(ClaimFailure(claimIndex: index, reason: "Claim at path \(pathStrings) not found"))
                continue
            }
            
            if let expectedClaimValues = claimQuery.values {
                if !matchesExpectedValues(claimValue, expectedValues: expectedClaimValues) {
                    failedClaims.append(ClaimFailure(claimIndex: index, reason: "Claim value at path \(pathStrings) does not match expected values"))
                    continue
                }
            }
            
            matchingClaimIndexes.append(index)
        }
        
        return (matchingClaimIndexes, failedClaims)
    }
    
    // Routes claim resolution based on credential type per spec Section 7
    private func resolveClaimValue(path: [String], credential: any ProcessedCredential) -> Any? {
        switch credential {
        case let mdoc as MdocCredential:
            return resolveMdocClaimPath(path, namespaces: mdoc.namespaces)
        case let w3c as W3cCredential:
            return resolveClaimPath(path, in: w3c.claims)
        case let sdJwt as SdJwtCredential:
            return resolveClaimPath(path, in: sdJwt.claims)
        default:
            return nil
        }
    }
    
    // Resolves a two-element mdoc path [namespace, elementIdentifier] per spec Section 7.2
    private func resolveMdocClaimPath(_ path: [String], namespaces: [String: [String: Any]]) -> Any? {
        guard path.count == 2,
              let namespaceElements = namespaces[path[0]] else { return nil }
        return namespaceElements[path[1]]
    }
    
    // Resolves a JSON claims path pointer (Section 7.1) recursively
    private func resolveClaimPath(_ path: [String], in claims: [String: Any]) -> Any? {
        guard let first = path.first else { return nil }
        let value = claims[first]
        if path.count == 1 { return value }
        guard let nested = value as? [String: Any] else { return nil }
        return resolveClaimPath(Array(path.dropFirst()), in: nested)
    }
    
    private func matchesExpectedValues(_ claimValue: Any, expectedValues: [ClaimValue]) -> Bool {
        for expected in expectedValues {
            switch expected {
            case .string(let value):
                if let actual = claimValue as? String, actual == value { return true }
            case .int(let value):
                if let actual = claimValue as? Int, actual == value { return true }
            case .bool(let value):
                if let actual = claimValue as? Bool, actual == value { return true }
            }
        }
        return false
    }
    
    // Checks meta constraints on format-specific meta keys
    private func matchesMeta(_ meta: [String: AnyCodable], walletCredential: any ProcessedCredential) -> Bool {
        switch walletCredential {
        case let sdJwt as SdJwtCredential:
            if let vctValues = meta["vct_values"]?.value as? [String] {
                return vctValues.contains(sdJwt.vct)
            }
            return false
        case let mdoc as MdocCredential:
            if let doctypeValue = meta["doctype_value"]?.value as? String {
                return mdoc.doctype == doctypeValue
            }
            return false
        case let w3c as W3cCredential:
            //TODO: Check if Type values are checked after expansion
            if let typeValues = meta["type_values"]?.value as? [[String]] {
                return typeValues.contains { requiredTypes in
                    requiredTypes.allSatisfy { w3c.type.contains($0) }
                }
            }
            return false
        default:
            return false
        }
    }
    
    // Builds CredentialSetRequirement array from dcqlQuery for the result
    private func buildCredentialSetRequirements(dcqlQuery: DCQLQuery) -> [CredentialSetRequirement] {
        guard let credentialSets = dcqlQuery.credentialSets else { return [] }
        return credentialSets.map { CredentialSetRequirement(options: $0.options, required: $0.required) }
    }
    
    // Checks if the full DCQL query is satisfied per spec Section 6.4.2
    private func isQuerySatisfied(queryMatches: [String: QueryMatchResult], credentialSets: [CredentialSetRequirement], dcqlQuery: DCQLQuery) -> Bool {
        if dcqlQuery.credentialSets == nil {
            // No credential_sets: all credential queries must be satisfied
            return queryMatches.values.allSatisfy { $0.candidateCredentials?.isEmpty == false }
        }
        
        // With credential_sets: all required sets must be satisfied; optional ones are ignored for success
        for credentialSet in credentialSets {
            guard credentialSet.required else { continue }
            
            let setIsSatisfied = credentialSet.options.contains { option in
                option.allSatisfy { credentialQueryId in
                    queryMatches[credentialQueryId]?.candidateCredentials?.isEmpty == false
                }
            }
            
            if !setIsSatisfied { return false }
        }
        
        return true
    }
    
}
