internal struct DcqlEvaluator {
    internal func evaluate(_ dcqlQuery: DCQLQuery, inputCredentials: [Credential]) throws -> QueryEvaluationResult {
        var filteredWalletCredentials: [Credential] = []
        var filteredWalletCredentialIds: [String] = []
        var queryMatches: [String: QueryMatchResult] = [:]
        
        // 1. Find all macthing credentials as per format
        let credentialFormatsInDCQLQuery = Set(dcqlQuery.credentials.map(\.format))
        let filteredFormatMatchingWalletCredentials = inputCredentials.filter { credentialFormatsInDCQLQuery.contains($0.format.rawValue) }
        
        if filteredFormatMatchingWalletCredentials.isEmpty {
            for credentialQuery in dcqlQuery.credentials {
                queryMatches[credentialQuery.id] = QueryMatchResult(
                    // TODO: Extract error code for this failure reason
                    failureReason: "No credentials found matching format for format : '\(credentialQuery.format)'",
                    allowMultipleCredentials: credentialQuery.multiple
                )
            }
            
            return QueryEvaluationResult(success: false, queryMatches: queryMatches, credentialSets: buildCredentialSetRequirements(dcqlQuery: dcqlQuery))
        }
        
        filteredWalletCredentials = filteredFormatMatchingWalletCredentials
        let credentialIdToCredential = Dictionary(uniqueKeysWithValues: filteredWalletCredentials.map { ($0.credentialId, $0) })
        let credentialIdToTags: [String: TaggedCredential] = try expandCredentialTags(credentialIdToCredential)
        
        // 2. Ensure meta and holderbinding as per request exist for all filtered credentials, otherwise throw
        
        var filteredCredentialIdsForMetaAndHolderBinding: [String] = []
        let dcqlCredentialQueriesByFormat = Dictionary(grouping: dcqlQuery.credentials, by: \.format)
        for walletCredentialData in filteredWalletCredentials {
            guard let walletCredential = credentialIdToTags[walletCredentialData.credentialId] else {
                throw InvalidData(message: "Credential tags not found for credential id: \(walletCredentialData.credentialId)", className: "DcqlEvaluator")
            }
            
            let dcqlQueriesAsPerFormat = dcqlCredentialQueriesByFormat[walletCredential.credentialFormat.rawValue] ?? []
            
            for credentialQuery in dcqlQueriesAsPerFormat {
                if matchesCryptographicHolderBinding(dcqlQueryRequestsCryptograhicHolderBinding: credentialQuery.requireCryptographicHolderBinding, walletCredential: walletCredential) {
                    // If at least one of the credential query matches add to the filtered list and move to next wallet credential, otherwise check for next query with same format
                    filteredCredentialIdsForMetaAndHolderBinding.append(walletCredentialData.credentialId)
                    break
                }
            }
        }
        
        if(filteredCredentialIdsForMetaAndHolderBinding.isEmpty) {
            for credentialQuery in dcqlQuery.credentials {
                queryMatches[credentialQuery.id] = QueryMatchResult(
                    // TODO: Extract error code for this failure reason
                    failureReason: "No credentials with cryptographic holder binding and meta filtering found for format '\(credentialQuery.format)'",
                    allowMultipleCredentials: credentialQuery.multiple
                )
            }
            
            return QueryEvaluationResult(success: false, queryMatches: queryMatches, credentialSets: buildCredentialSetRequirements(dcqlQuery: dcqlQuery))
        }

        
        // Apply meta and holder binding filtering here as needed (placeholder keeps current behavior)
        filteredWalletCredentialIds = filteredCredentialIdsForMetaAndHolderBinding
        
        let processedCredentials = try convertToProcessedCredentials(filteredWalletCredentialIds, credentialIdToCredential)
        
        for credentialQuery in dcqlQuery.credentials {
            queryMatches[credentialQuery.id] = evaluateCredentialQuery(credentialQuery, against: processedCredentials)
        }
        
        let credentialSetRequirements = buildCredentialSetRequirements(dcqlQuery: dcqlQuery)
        let success = isQuerySatisfied(queryMatches: queryMatches, credentialSets: credentialSetRequirements, dcqlQuery: dcqlQuery)
        
        return QueryEvaluationResult(success: success, queryMatches: queryMatches, credentialSets: credentialSetRequirements)
    }
    
    private func evaluateCredentialQuery(_ credentialQuery: CredentialQuery, against walletCredentials: [any ProcessedCredential]) -> QueryMatchResult {
        var filteredWalletCredentials: [any ProcessedCredential] = []
        
        // 3. Apply the claims level check
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
    
    private func matchesMeta(_ meta: [String: AnyCodable], walletCredential: any TaggedCredential) -> Bool {
        switch walletCredential {
        case let sdJwt as SdJwtTaggedCredential:
            if let vctValues = meta["vct_values"]?.value as? [String] {
                return vctValues.contains(sdJwt.vct)
            }
            return false
        case let mdoc as MdocTaggedCredential:
            if let doctypeValue = meta["doctype_value"]?.value as? String {
                return mdoc.doctype == doctypeValue
            }
            return false
        case let w3c as W3cTaggedCredential:
            //TODO: Check if Type values are checked after expansion
            if let typeValues = meta["type_values"]?.value as? [[String]] {
                return typeValues.contains { requiredTypes in
                    requiredTypes.allSatisfy { w3c.types.contains($0) }
                }
            }
            return false
        default:
            return false
        }
    }
    
    private func matchesCryptographicHolderBinding(dcqlQueryRequestsCryptograhicHolderBinding: Bool, walletCredential: any TaggedCredential) -> Bool {
        switch walletCredential {
        case let sdJwt as SdJwtTaggedCredential:
            // If dcqlQueryRequestsCryptograhicHolderBinding and credential has cryptographic holder binding, then it's a match.
            // If dcqlQueryRequestsCryptograhicHolderBinding is false, then we don't need to check for cryptographic holder binding capability and it's a match regardless of credential's capability
            return !dcqlQueryRequestsCryptograhicHolderBinding || sdJwt.hasCryptographicHolderBinding
        case let mdoc as MdocTaggedCredential:
           return dcqlQueryRequestsCryptograhicHolderBinding && mdoc.hasCryptographicHolderBinding
        case let w3c as W3cTaggedCredential:
            return dcqlQueryRequestsCryptograhicHolderBinding && w3c.hasCryptographicHolderBinding
        default:
            return false
        }
    }
    
    // Builds CredentialSetRequirement array from dcqlQuery for the result
    private func buildCredentialSetRequirements(dcqlQuery: DCQLQuery) -> [CredentialSetQuery] {
        guard let credentialSets = dcqlQuery.credentialSets else { return [] }
        return credentialSets.map { CredentialSetQuery(options: $0.options, required: $0.required) }
    }
    
    // Checks if the full DCQL query is satisfied per spec Section 6.4.2
    private func isQuerySatisfied(queryMatches: [String: QueryMatchResult], credentialSets: [CredentialSetQuery], dcqlQuery: DCQLQuery) -> Bool {
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
