internal struct DcqlEvaluator {
    private let jsonLdExpander: JsonLdExpanding
    
    public init(jsonLdExpander: JsonLdExpanding) {
        self.jsonLdExpander = jsonLdExpander
    }
    
    internal func evaluate(_ dcqlQuery: DCQLQuery, inputCredentials: [Credential]) async throws -> MatchingCredentialsResult {
        var queryMatches: [String: QueryMatchResult] = [:]
        
        
        let credentialsByFormat = Dictionary(grouping: inputCredentials, by: { $0.format.rawValue })
        let credentialIdToCredential = Dictionary(
            inputCredentials.map { ($0.credentialId, $0) },
            uniquingKeysWith: { _, last in last }
        )
        
        // Local caches to ensure we only do work ONCE
        var credentialsTagCache: [String: TaggedCredential] = [:]
        var processedCredentialsCache: [String: any ProcessedCredential] = [:]
        
        for credentialQuery in dcqlQuery.credentials {
            // 1. Format check
            guard let formatMatchingCredentials = credentialsByFormat[credentialQuery.format], !formatMatchingCredentials.isEmpty else {
                queryMatches[credentialQuery.id] = QueryMatchResult(failureReason: .noMatchingFormatsFound, allowMultipleCredentials: credentialQuery.multiple)
                continue
            }
            
            // 2. Cryptographic Holder Binding and Meta check
            var metaAndBindingMatchingIds: [String] = []
            for credential in formatMatchingCredentials {
                let credentialId = credential.credentialId

                if credentialsTagCache[credentialId] == nil {
                    credentialsTagCache[credentialId] = try await expandCredentialTag(credential, jsonLdExpander: self.jsonLdExpander)
                }

                guard let credentialTag = credentialsTagCache[credentialId] else { continue }

                let holderBindingAndMetaMatchSuccess = matchesCryptographicHolderBinding(
                    dcqlQueryRequestsCryptograhicHolderBinding: credentialQuery.requireCryptographicHolderBinding,
                    walletCredential: credentialTag
                ) && matchesMeta(credentialQuery.meta, walletCredential: credentialTag)

                if holderBindingAndMetaMatchSuccess {
                    metaAndBindingMatchingIds.append(credentialId)
                }
            }
            
            if metaAndBindingMatchingIds.isEmpty {
                queryMatches[credentialQuery.id] = QueryMatchResult(failureReason: .cryptographicHolderBindingOrMetaFilterMismatch, allowMultipleCredentials: credentialQuery.multiple)
                continue
            }
            
            // 3. Claims level check
            let applicableInputCredentials = try getOrProcessApplicableCredentials(
                matchingIds: metaAndBindingMatchingIds,
                credentialIdToCredential: credentialIdToCredential,
                processedCache: &processedCredentialsCache
            )
            
            queryMatches[credentialQuery.id] = evaluateCredentialQueryClaims(credentialQuery, against: applicableInputCredentials)
        }
        
        let credentialSetRequirements = buildCredentialSetRequirements(dcqlQuery: dcqlQuery)
        let success = isQuerySatisfied(queryMatches: queryMatches, credentialSets: credentialSetRequirements, dcqlQuery: dcqlQuery)
        
        return MatchingCredentialsResult(success: success, queryMatches: queryMatches, credentialSets: credentialSetRequirements)
    }
    
    /**
     * Processes missing credentials, caches them, and returns all credentials matching the provided IDs.
     */
    func getOrProcessApplicableCredentials(
        matchingIds: [String],
        credentialIdToCredential: [String: Credential],
        processedCache: inout [String: any ProcessedCredential]
    ) throws -> [any ProcessedCredential] {
        let matchingIdsSet = Set(matchingIds)
        let nonProcessedIds = matchingIdsSet.filter { processedCache[$0] == nil }.map { String($0) }
        
        if !nonProcessedIds.isEmpty {
            let newProcessed = try convertToProcessedCredentials(nonProcessedIds, credentialIdToCredential)
            processedCache.merge(newProcessed) { (_, new) in new }
        }
        
        return matchingIds.compactMap { processedCache[$0] }
    }
    
    private func evaluateCredentialQueryClaims(_ credentialQuery: CredentialQuery, against walletCredentials: [any ProcessedCredential]) -> QueryMatchResult {
        if(credentialQuery.claims == nil) {
            // If no claims are requested, then all credentials that passed format, meta and holder binding checks are candidate credentials
            let matchingCredentials = walletCredentials.map { MatchingCredential(credentialId: $0.credentialId, matchingClaims: []) }
            return QueryMatchResult(matchingCredentials: matchingCredentials, allowMultipleCredentials: credentialQuery.multiple)
        }
        
        var matchingCredentials: [MatchingCredential] = []
        var failedClaims: [ClaimFailure] = []
        var claimsCheckFailureReason: DCQLEvaluationErrorCodes? = nil
        
        for walletCredential in walletCredentials {
            let (matchingClaims, claimFailures, failureReason) = evaluateClaims(credentialQuery: credentialQuery, walletCredential: walletCredential)
            
            if claimFailures.isEmpty {
                matchingCredentials.append(MatchingCredential(credentialId: walletCredential.credentialId, matchingClaims: matchingClaims))
            } else {
                // Failed claims holds the reason for claims check failure which deos not include any details about credential
                failedClaims.append(contentsOf: claimFailures)
                claimsCheckFailureReason = failureReason
            }
        }
        
        if matchingCredentials.isEmpty {
            return QueryMatchResult(failedClaims: failedClaims.isEmpty ? nil : failedClaims, failureReason: claimsCheckFailureReason, allowMultipleCredentials: credentialQuery.multiple)
        }
        
        return QueryMatchResult(matchingCredentials: matchingCredentials, allowMultipleCredentials: credentialQuery.multiple)
    }
    
    // Evaluates claims and claim_sets
    private func evaluateClaims(credentialQuery: CredentialQuery, walletCredential: any ProcessedCredential) -> (matchingClaims: [ClaimsQuery], failedClaims: [ClaimFailure], failureReason: DCQLEvaluationErrorCodes?) {
        // If no claims is available in VP request, all mandatory claims of the credential needs to be shared to Verifier
        guard let claims = credentialQuery.claims else {
            return ([], [], nil)
        }
        
        // One of the options of the claim_sets needs to be satisfied if claim_sets is present in the VP request.
        
        if let claimSets = credentialQuery.claimSets {
            // claim_sets are ordered by preference, so we iterate through the options and return as soon as we find a satisfied option
            var failedClaimSetQuery: [ClaimFailure] = []
            for claimSetOption in claimSets {
                //TODO: If claim set is there claim id is mandatory add that check instead of fallback to ""
                let requestedClaims = claims.filter { claimSetOption.contains($0.id ?? "") }
                let (matchingClaims, failedClaims) = checkClaims(requestedClaims, walletCredential: walletCredential)
                
                // Once the claim_set option with all claims satisfied is found, return the result without evaluating further options as claim_sets are in order of preference
                if failedClaims.isEmpty {
                    return (matchingClaims, [], nil)
                }
                failedClaimSetQuery.append(contentsOf: failedClaims)
            }
            // Populate all claim failure reason
            return ([], failedClaimSetQuery, .noClaimsSetOptionSatisfied)
        }
        
        // If claim_sets is not present, then all claims in the VP request need to be satisfied
        let (matchingClaims, failedClaims) = checkClaims(claims, walletCredential: walletCredential)
        return (matchingClaims, failedClaims, nil)
    }
    
    private func checkClaims(_ claims: [ClaimsQuery], walletCredential: any ProcessedCredential) -> (matchingClaims: [ClaimsQuery], failedClaims: [ClaimFailure]) {
        var matchingClaims: [ClaimsQuery] = []
        var failedClaims: [ClaimFailure] = []
        
        for claimQuery in claims {
            let pathStrings = claimQuery.path.compactMap { $0.value as? String }
            
            guard let claimValue = resolveClaimValue(path: pathStrings, credential: walletCredential) else {
                failedClaims.append(ClaimFailure(claim: claimQuery, reason: .claimUnavailable))
                continue
            }
            
            if let expectedClaimValues = claimQuery.values {
                if !matchesExpectedValues(claimValue, expectedValues: expectedClaimValues) {
                    failedClaims.append(ClaimFailure(claim: claimQuery, reason: .claimValueMismatch))
                    continue
                }
            }
            
            matchingClaims.append(claimQuery)
        }
        
        return (matchingClaims, failedClaims)
    }
    
    // Routes claim resolution based on credential type per spec Section 7
    private func resolveClaimValue(path: [String], credential: any ProcessedCredential) -> Any? {
        switch credential {
        case let mdoc as MdocProcessedCredential:
            return resolveMdocClaimPath(path, namespaces: mdoc.namespaces)
        case let w3c as W3cProcessedCredential:
            return resolveClaimPath(path, in: w3c.claims)
        case let sdJwt as SdJwtProcessedCredential:
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
        if(meta.isEmpty) {
            return true
        }
        
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
            return queryMatches.values.allSatisfy { $0.matchingCredentials?.isEmpty == false }
        }
        
        // With credential_sets: all required sets must be satisfied; optional ones are ignored for success
        for credentialSet in credentialSets {
            guard credentialSet.required else { continue }
            
            let setIsSatisfied = credentialSet.options.contains { option in
                option.allSatisfy { credentialQueryId in
                    queryMatches[credentialQueryId]?.matchingCredentials?.isEmpty == false
                }
            }
            
            if !setIsSatisfied { return false }
        }
        
        return true
    }
    
}
