# Migration Guide: inji-openid4vp-ios-swift 0.7.0 → 1.0.0

This guide helps Swift developers upgrade from **`inji-openid4vp-ios-swift` 0.7.0** to **1.0.0**.

Scope: **breaking changes in the Swift entry point(s)** - OpenID4VP class and its public API. 

Note: 
- The core flow and concepts remain the same, but method signatures and some data models have changed for better clarity and usability.
---

## Quick method communication overview

1. `OpenID4VP(traceabilityId:walletConfig:jsonLdCanonicalizer:)` initializes wallet capabilities and trusted verifier defaults.
2. `authenticateVerifier(...)` validates the incoming authorization request and stores request context for the session.
3. `constructUnsignedVPToken(selectedCredentials:)` builds signing work units (`[UnsignedVPToken]`) from user-approved credentials.
4. Your wallet signs each `UnsignedVPToken.dataToSign` using `holderKeyReference` and `signatureAlgorithm`, producing `[VPTokenSigningResult]`.
5. `constructVPResponse(...)` or `sendVPResponseToVerifier(...)` generates/sends the final VP response.

---

## Feature overview

1. 0.7.0
   1. Supported OpenID4VP draft 21 and draft 23, mainly Presentation Definition flows.
2. 1.0.0
   1. Supports OpenID4VP draft 23 (Presentation Definition) and 1.0 (DCQL).
   2. Removed draft 21 support.
   3. Improves integration by:
      - returning structured signing units (`UnsignedVPToken`) instead of opaque encoded blocks
      - centralizing capability and verifier settings in `WalletConfig`

---

## TL;DR (what you must change)

1. `OpenID4VP` construction changed:
   - **0.7.0**: `OpenID4VP(traceabilityId:walletMetadata:)`
   - **1.0.0**: `OpenID4VP(traceabilityId:walletConfig:jsonLdCanonicalizer:)` (`walletConfig` has defaults)

2. `constructUnsignedVPToken(...)` changed significantly:
   - **0.7.0**: `constructUnsignedVPToken(verifiableCredentials:holderId:signatureSuite:)` accepted `[String: [FormatType: [AnyCodable]]]` and returned `[FormatType: UnsignedVPToken]`
   - **1.0.0**: `constructUnsignedVPToken(selectedCredentials:)` accepts `[String: [Credential]]` and returns `[UnsignedVPToken]`; `holderId` / `signatureSuite` are no longer inputs

3. VP response construction/sending changed:
   - `constructVPResponse(vpTokenSigningResults:)` accepts `[VPTokenSigningResult]`
   - `sendVPResponseToVerifier(vpTokenSigningResults:)` accepts `[VPTokenSigningResult]`

4. For DCQL request processing, use `DCQLHelper.getMatchingCredentials(inputCredentials:dcqlQuery:)` to match wallet's available credentials against incoming VP request before building `selectedCredentials`.

5. Deprecated and legacy V1/V2 0.7.0 entry-point methods are removed in 1.0.0, while the core methods remain with updated signatures.

---

## Before vs After: entry point construction

### 0.7.0 (old)

```swift
// Legacy 0.7.0 style (for migration reference)
let openID4VP = OpenID4VP(
    traceabilityId: "trace-id",
    walletMetadata: walletMetadata
)
```

### 1.0.0 (new)

```swift
import OpenID4VP

let walletConfig = WalletConfig(
    trustedVerifiers: trustedVerifiers,
    validateTrustedVerifier: true,
    // Optional: override defaults such as
    // vpFormatsSupported, clientIdPrefixesSupported,
    // requestObjectSigningAlgValuesSupported, etc.
)

let openID4VP = OpenID4VP(
    traceabilityId: "trace-id",
    walletConfig: walletConfig,
    jsonLdCanonicalizer: nil // Optional callback; required when processing W3C credentials that need JSON-LD canonicalization.
)
```

Reference: `Sources/OpenID4VP/OpenID4VP.swift`

### Mapping `WalletMetadata` -> `WalletConfig`

If your 0.7.0 integration used the old Swift wallet metadata model below:

```swift
public struct WalletMetadata: Codable {
    let presentationDefinitionURISupported: Bool
    let vpFormatsSupported: [VPFormatType: VPFormatSupported]
    let clientIdSchemesSupported: [ClientIdScheme]
    var requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]?
    let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]?
    let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]?
    let responseTypesSupported: [ResponseType]
}
```

then migrate it to `WalletConfig` like this:

| Old `WalletMetadata` field                  | New `WalletConfig` parameter                | Migration note                                                |
|---------------------------------------------|---------------------------------------------|---------------------------------------------------------------|
| `presentationDefinitionURISupported`        | `isPresentationDefinitionUriSupported`      | Same capability, naming updated                               |
| `vpFormatsSupported`                        | `vpFormatsSupported`                        | Same capability                                               |
| `clientIdSchemesSupported`                  | `clientIdPrefixesSupported`                 | `ClientIdScheme` values map to public `ClientIdPrefix` values |
| `requestObjectSigningAlgValuesSupported`    | `requestObjectSigningAlgValuesSupported`    | `RequestSigningAlgorithm` -> `SignatureAlgorithm`             |
| `authorizationEncryptionAlgValuesSupported` | `authorizationEncryptionAlgValuesSupported` | `KeyManagementAlgorithm` -> `EncryptionAlgorithm`             |
| `authorizationEncryptionEncValuesSupported` | `authorizationEncryptionEncValuesSupported` | `ContentEncryptionAlgorithm` -> `EncryptionMethod`            |
| `responseTypesSupported`                    | `responseTypesSupported`                    | Same capability - Response Types supported by the Wallet      |
| `presentationDefinitionURISupported`        | `isPresentationDefinitionUriSupported`      | Same capability  - Supports `presentation_definition_uri`     |

Additional fields now configured on `WalletConfig` in 1.0.0:

| `WalletConfig`-only field              | Purpose                                        | Migration note                                                             |
|----------------------------------------|------------------------------------------------|----------------------------------------------------------------------------|
| `requestUriMethodsSupported`           | Supported `request_uri_method` values          |                                                                            |
| `trustedVerifiers`                     | Default Wallet's pre-registered Verifiers list | Previously accepted as `trustedVerifiers` in `authenticateVerifier` method |

Example migration:

```swift
let walletConfig = WalletConfig(
    isPresentationDefinitionUriSupported: true,
    vpFormatsSupported: [
        .ldp_vc: LdpVcFormatSupported(
            proofTypeValues: [.jsonWebSignature2020],
            cryptoSuiteValues: []
        ),
        .mso_mdoc: MsoMdocVcFormatSupported(
            issuerAuthAlgValues: [-7],
            deviceAuthAlgValues: [-7]
        ),
        .dc_sd_jwt: SdJwtVcFormatSupported(
            sdJwtAlgValues: ["ES256"],
            kbJwtAlgValues: ["ES256"]
        )
    ],
    clientIdPrefixesSupported: [.preRegistered, .redirectUri, .decentralizedIdentifier],
    requestObjectSigningAlgValuesSupported: [.edDsa],
    authorizationEncryptionAlgValuesSupported: [.ecdhES],
    authorizationEncryptionEncValuesSupported: [.a256GCM],
    responseTypesSupported: [.vp_token],
    trustedVerifiers: [
        Verifier(
            clientId: "inji-mock-verify",
            responseUris: ["https://mock-verifier.inji.com/response"],
            jwksUri: "https://mock-verifier.inji.com/.well-known/jwks.json",
            allowUnsignedRequest: true
        )
    ]
)
```

Notes:
- `ClientIdScheme.did` maps to `ClientIdPrefix.decentralizedIdentifier` in the current API.
- `requestUriMethodsSupported` and `trustedVerifiers` are new `WalletConfig` concerns that were not part of this older `WalletMetadata` model.
- For the algorithm/encryption enums, direct `rawValue` conversion works when the old and new enum raw values match.

---

## Before vs After: `authenticateVerifier(...)`

### What stays conceptually the same
- You still validate verifier authorization requests and receive `AuthorizationRequest`.

### What changes in practice

1. **Trusted verifier configuration is now part of `WalletConfig`**

    * Configure trusted verifiers once via `walletConfig.trustedVerifiers`.
    * Do not pass trusted verifiers to `authenticateVerifier(...)`.

2. **Validation of pre-registered VP request clients is now configured through `WalletConfig`**

    * Configure the validation flag via `walletConfig.validateTrustedVerifier`.
    * Do not pass `shouldValidateClient` to `authenticateVerifier(...)`.

3. **Deprecated 0.7.0 overloads have been removed**

    * Overloads that accepted metadata or trust-related parameters at call time are no longer supported.


### 0.7.0 call signatures (old)

```swift
let authorizationRequest = try await openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest: encodedAuthorizationRequest,
    trustedVerifiers: trustedVerifiers,
    shouldValidateClient: true
)
```

```swift
let authorizationRequest = try await openID4VP.authenticateVerifier(
    authorizationRequest: authorizationRequestMap,
    trustedVerifiers: trustedVerifiers,
    shouldValidateClient: true
)
```

### 1.0.0 call (URL-encoded)

```swift
let authorizationRequest = try await openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest: encodedAuthorizationRequest
)
```

### 1.0.0 call (dictionary input)

```swift
let authorizationRequest = try await openID4VP.authenticateVerifier(
    authorizationRequest: authorizationRequestMap
)
```

Reference: `Sources/OpenID4VP/OpenID4VP.swift`

---

## Before vs After: `constructUnsignedVPToken(...)` (biggest change)

### Old behavior (0.7.0)

In 0.7.0, the main public method was:

```swift
let unsignedVPTokensByFormat: [FormatType: UnsignedVPToken] = try await openID4VP.constructUnsignedVPToken(
    verifiableCredentials: verifiableCredentials,
    holderId: holderId,
    signatureSuite: signatureSuite
)
```

Where:
- `verifiableCredentials` type was `[String: [FormatType: [AnyCodable]]]`
- the return type was `[FormatType: UnsignedVPToken]`
- `holderId` and `signatureSuite` were optional inputs used by older LDP VP construction flows

0.7.0 also exposed `constructUnsignedVPTokenV2(...) -> [UnsignedVPTokenV2]`, which is removed in 1.0.0.

### New behavior (1.0.0)

In 1.0.0, `constructUnsignedVPToken(selectedCredentials:)` returns **typed list of signing work units**:

```swift
let unsignedVPTokens: [UnsignedVPToken] = try await openID4VP.constructUnsignedVPToken(
    selectedCredentials: selectedCredentials
)
```

`selectedCredentials` shape:
- type: `[String: [Credential]]`
- key: `input_descriptor.id` (Presentation Definition) or `credential_query.id` (DCQL)
- value: selected credentials where each `Credential` has:
  - `format: FormatType`
  - `data: AnyCodable`
  - `credentialId: String`

Example:

```swift
let selectedCredentials: [String: [Credential]] = [
    "age_descriptor": [
        Credential(
            format: .ldp_vc,
            data: AnyCodable([
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "AgeCredential"],
                "credentialSubject": [
                    "id": "did:example:holder-001",
                    "ageOver18": true
                ]
            ]),
            credentialId: "cred-age-001"
        )
    ],
    "email_query": [
        Credential(
            format: .dc_sd_jwt,
            data: AnyCodable("<compact-dc-sd-jwt-vc>"),
            credentialId: "cred-email-777"
        )
    ]
]
// Note: The credentials shown here are for illustrative purposes.
```

`holderId` and `signatureSuite` are removed from this API. 1.0.0 resolves signing requirements inside the SDK and returns them via `UnsignedVPToken`.

Each `UnsignedVPToken` provides:
- `format: FormatType`
- `holderKeyReference: String`
- `signatureAlgorithm: String`
- `dataToSign: Data`

Wallet signing step:

```swift
let vpTokenSigningResults: [VPTokenSigningResult] = try unsignedVPTokens.map { unsignedVPToken in
    let signature: Data = try walletKeyManager.sign(
        data: unsignedVPToken.dataToSign,
        keyReference: unsignedVPToken.holderKeyReference,
        algorithm: unsignedVPToken.signatureAlgorithm
    )

    return VPTokenSigningResult(id: unsignedVPToken.id, signedData: signature)
}
```

References:
- `Sources/OpenID4VP/OpenID4VP.swift`
- `Sources/OpenID4VP/AuthorizationResponse/UnsignedVPToken/UnsignedVPToken.swift`
- `Sources/OpenID4VP/AuthorizationResponse/VPTokenSigningResult/VpTokenSigningResult.swift`

---

## Before vs After: `constructVPResponse(...)`

### 0.7.0 (old)

```swift
let response: [String: Any] = openID4VP.constructVPResponse(
    vpTokenSigningResults: oldSigningResultsByFormat
)
```

Signature:
- `constructVPResponse(vpTokenSigningResults: [FormatType: VPTokenSigningResult]) -> [String: Any]`

### 1.0.0 usage

```swift
let response: [String: Any] = openID4VP.constructVPResponse(
    vpTokenSigningResults: vpTokenSigningResults
)
```

Signature:
- `constructVPResponse(vpTokenSigningResults: [VPTokenSigningResult]) -> [String: Any]`

Behavior note:
- If VP response construction fails internally, it returns error info (`constructErrorInfo(exception:)`) instead of throwing.

---

## DCQL helper: `getMatchingCredentials(...)` from `DCQLHelper`

In 1.0.0, DCQL credential matching is available via `DCQLHelper`:

```swift
import OpenID4VP

let dcqlHelper = DCQLHelper(
    jsonLdExpander: nil // Optional callback to pre-expand credential JSON-LD before evaluation
)

let matchingResult = try await dcqlHelper.getMatchingCredentials(
    inputCredentials: walletAvailableCredentials,
    dcqlQuery: dcqlQuery
)
```

Use this to evaluate all wallet credentials against incoming DCQL constraints before calling `constructUnsignedVPToken(selectedCredentials:)`.

You can down-cast the validated request to `AuthorizationDcqlRequest` and use its public `dcqlQuery` to run DCQL matching with `DCQLHelper`.

Reference: `Sources/OpenID4VP/Helpers/DCQLHelper.swift`

---

## Before vs After: `sendVPResponseToVerifier(...)`

### 0.7.0 (old)

```swift
let verifierResponse: VerifierResponse = try await openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults: oldSigningResultsByFormat
)
```

Signature:
- `sendVPResponseToVerifier(vpTokenSigningResults: [FormatType: VPTokenSigningResult]) async throws -> VerifierResponse`

### 1.0.0 usage

```swift
let verifierResponse: VerifierResponse = try await openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults: vpTokenSigningResults
)
```

Signature:
- `sendVPResponseToVerifier(vpTokenSigningResults: [VPTokenSigningResult]) async throws -> VerifierResponse`

---

## Removed and changed entry-point methods from 0.7.0 (update your call sites)

> **Notice**
>
> 1.0.0 keeps the core entry point class, but several 0.7.0 methods were removed and some existing methods changed signatures.

Current public methods in `OpenID4VP` 1.0.0:
- `authenticateVerifier(urlEncodedAuthorizationRequest:shouldValidateClient:)`
- `authenticateVerifier(authorizationRequest:shouldValidateClient:)`
- `constructUnsignedVPToken(selectedCredentials:)`
- `constructVPResponse(vpTokenSigningResults:)`
- `constructErrorInfo(exception:)`
- `sendVPResponseToVerifier(vpTokenSigningResults:)`
- `sendErrorInfoToVerifier(error:)`

For DCQL matching, use `DCQLHelper`:
- `getMatchingCredentials(inputCredentials:dcqlQuery:) async throws -> MatchingCredentialsResult`

For detailed usage refer the [latest integration guide](../integration-guide.md)

### API Signature Changes

The following APIs have updated signatures in 1.0.0:

* `authenticateVerifier(urlEncodedAuthorizationRequest:shouldValidateClient:)`

    * Trusted verifier configuration is now sourced from `WalletConfig` and is no longer passed at call time.

* `authenticateVerifier(authorizationRequest:shouldValidateClient:)`

    * Trusted verifier configuration is now sourced from `WalletConfig` and is no longer passed at call time.

* `constructUnsignedVPToken(selectedCredentials:)`

    * VP construction now operates on selected credentials directly, removing the need to provide holder identifiers and signature suites at call time.

* `constructVPResponse(vpTokenSigningResults: [VPTokenSigningResult])`

    * The signing result collection no longer requires a `FormatType` mapping.

* `sendVPResponseToVerifier(vpTokenSigningResults: [VPTokenSigningResult])`

    * The signing result collection no longer requires a `FormatType` mapping.

The following APIs are unchanged in 1.0.0:

* `constructErrorInfo(exception:)`
* `sendErrorInfoToVerifier(error:)`


0.7.0 methods removed in 1.0.0:
- `constructUnsignedVPTokenV2(...)`
- `constructVPResponseV2(...)`
- `shareVerifiablePresentation(vpTokenSigningResults:)`
- `authenticateVerifier(urlEncodedAuthorizationRequest:trustedVerifierJSON:shouldValidateClient:walletMetadata:)`
- `authenticateVerifier(urlEncodedAuthorizationRequest:trustedVerifierJSON:shouldValidateClient:)`
- `constructVerifiablePresentationToken(verifiableCredentials:)`
- `shareVerifiablePresentation(vpResponseMetadata:)`
- `sendErrorToVerifier(error:)`

---

## Minimal working Swift example in 1.0.0

```swift
import Foundation
import OpenID4VP

func handleOVPFlow(
    applicationId: String,
    
    encodedAuthorizationRequest: String,
    
    trustedVerifiers: [Verifier],
    /*...Other wallet configurations..*/
    
    walletAvailableCredentials: [Credential]
) async throws -> Void {
    let walletConfig = WalletConfig(trustedVerifiers: trustedVerifiers, /*...Other wallet configurations..*/)
    let credentialById = Dictionary(uniqueKeysWithValues: walletAvailableCredentials.map { ($0.credentialId, $0) })

    let openID4VP = OpenID4VP(
        traceabilityId: applicationId,
        walletConfig: walletConfig,
        jsonLdCanonicalizer: jsonLdCanonicalizerCallback //Required only if ldp_vcs support is required otherwise Optional, can be nil if not needed
    )

    do {
        let validatedVPRequest = try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: encodedAuthorizationRequest
        )

        var selectedCredentials: [String: [Credential]] = [:]
            

        if let vpRequest = validatedVPRequest as? AuthorizationDcqlRequest {
            // DCQL flow
            let dcqlHelper = DCQLHelper(jsonLdExpander: nil)
            let matchingVcsResult = try await dcqlHelper.getMatchingCredentials(
                inputCredentials: walletAvailableCredentials,
                dcqlQuery: vpRequest.dcqlQuery
            )
            let result = getShareableCredentialsWithConsent(matchingVcsResult)
            
            if(result.userConsentRejected) {
                let vpRejectionVerifierResponse = try await openID4VP.sendErrorInfoToVerifier(error: AccessDenied(message: "User rejected to share credentials", className: "SampleWalletApp"))
                handleVeriferResponse(vpRejectionVerifierResponse)
            } else {
                selectedCredentials = result.selectedCredentials
            }
        } else {
            // Presentation Exchange flow
            let vpRequest = (validatedVPRequest as? AuthorizationPresentationExchangeRequest) ?? {fatalError("Unexpected request type")}()
            let result = getCredentialsForVPRequestWithConsent(vpRequest)
            
            if(result.userConsentRejected) {
                let vpRejectionVerifierResponse = try await openID4VP.sendErrorInfoToVerifier(error: AccessDenied(message: "User rejected to share credentials", className: "SampleWalletApp"))
                handleVeriferResponse(vpRejectionVerifierResponse)
            } else {
                selectedCredentials = result.selectedCredentials
            }
        }

        let unsignedVpTokens = try await openID4VP.constructUnsignedVPToken(
            selectedCredentials: selectedCredentials
        )
        
        let signingResults = try unsignedVpTokens.map { unsignedVPToken in
            let signature = try signData(
                unsignedVPToken.dataToSign,
                keyReference: unsignedVPToken.holderKeyReference,
                algorithm: unsignedVPToken.signatureAlgorithm
            )
            return VPTokenSigningResult(id: unsignedVPToken, signedData: signature)
        }

        let vpSubmissionVerifierResponse = try await openID4VP.sendVPResponseToVerifier(
            vpTokenSigningResults: signingResults
        )
        handleVeriferResponse(vpSubmissionVerifierResponse)
    } catch {
       // Show error screen as per error -> error.errorCode / error.message and handle verifier response if available -> error.verifierResponse
    }
}


// Helpers

func jsonLdCanonicalizerCallback(_ data: String) async throws -> String {
    // 1. Parse the input JSON string into a data structure - unsignedVP

    guard let jsonData = data.data(using: .utf8),
          var unsignedVP = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any]
    else {
        // handle error
        return ""
    }

    // 2. Extract @context
    let context = unsignedVP["@context"]

    // 3. Extract proof and attach context
    var jsonLdProof: [String: Any] = [:]
    if let proof = unsignedVP["proof"] as? [String: Any] {
        jsonLdProof = proof
        jsonLdProof["@context"] = context ?? NSNull()
    }

    // 4. Remove proof from VP
    var jsonldObjectClone = unsignedVP
    jsonldObjectClone.removeValue(forKey: "proof")

    func toJSONString(_ obj: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        guard let str = String(data: data, encoding: .utf8) else {
            // handle error
            return ""
        }
        return str
    }

    func jsonldCanonize(_ obj: Any) async throws -> String {
        // Implement your JSON-LD canonicalization logic here
        // For demonstration, we are just returning empty string
        return ""
    }
    func sha256(_ input: Data) -> Data {
        // Implement SHA-256 hashing of the input data
        // For demonstration, we are just returning the input data. Replace this with actual hashing logic.
        return input
    }
    func base64urlEncode(_ input: Data) -> String {
        // Implement your base64URL encoding logic here
        // For demonstration, we are just returning empty string
        return ""
    }

    // 5. Canonicalize unsignedVP
    let normalizedJsonldObject = try await jsonldCanonize(jsonldObjectClone)

    // 6. Canonicalize jsonLdProof
    let normalizedJsonldProof = try await jsonldCanonize(jsonLdProof)

    // 7. Combine hashes (SHA-256)
    let proofHash = sha256(Data(normalizedJsonldProof.utf8))
    let objectHash = sha256(Data(normalizedJsonldObject.utf8))
    var hashData = Data()
    hashData.append(proofHash)
    hashData.append(objectHash)


    return base64urlEncode(hashData)
}

func jsonLdExpanderCallback(_ data: [String: Any]) async throws -> [String: Any] {
    // Implement your JSON-LD expansion logic here
    // 1. Take the input data and expand it according to the JSON-LD context and rules
    // For demonstration, we are just returning the input data
    return data
}

func getShareableCredentialsWithConsent(_ matchingVcsResult: MatchingCredentialsResult) -> (selectedCredentials: [String: [Credential]], userConsentRejected: Bool) {
    // Implement your logic to filter and select credentials based on user consent
    // 1. Take the matchingVcsResult which contains the credentials that match the DCQL query
    // 2. Present these credentials to the user and ask for their consent to share them with the verifier
    // 3. Based on the user's consent, filter the credentials and return only those that the user has agreed to share
    // For demonstration, we are just returning empty map here and consent as not rejected
    return ([:], false)
}

func getCredentialsForVPRequestWithConsent(_ vpRequest: AuthorizationPresentationExchangeRequest) -> (selectedCredentials: [String: [Credential]], userConsentRejected: Bool) {
    // Implement your logic to filter available wallet credentials based on the requirements in the VP request, select credentials and get user consent
    // For demonstration, we are just returning empty map here and consent as not rejected
    return ([:], false)
}

func signData(_ data: Data, keyReference: String, algorithm: String) throws -> Data {
    // Implement your signing logic here
    return Data()
}

func handleVeriferResponse(_ verifierResponse: VerifierResponse) -> Void {
    // Implement your logic to handle the response from the verifier after sending the VP response
    // Show successful submission message to the user if the response indicates success, otherwise show an error message
    // redirect to verifierResponse.redirectUri if available
}
```

Notes:
- The crypto implementations like signing data is kept in your wallet app while the SDK focuses on VP request validation/VP response construction and sending to Verifier.

---

## Appendix: Key Swift Types and Entry Points

The following files contain the primary types and APIs used throughout the SDK:

* **Entry point**
    * `Sources/OpenID4VP/OpenID4VP.swift`
* **Wallet configuration and credential models**
    * `Sources/OpenID4VP/Wallet/WalletConfig.swift`
    * `Sources/OpenID4VP/Wallet/Credential.swift`
* **DCQL utilities**
    * `Sources/OpenID4VP/Helpers/DCQLHelper.swift`
* **Signing work units**
    * `Sources/OpenID4VP/AuthorizationResponse/UnsignedVPToken/UnsignedVPToken.swift`
    * `Sources/OpenID4VP/AuthorizationResponse/VPTokenSigningResult/VPTokenSigningResult.swift`
* **Callback type definitions**
    * `Sources/OpenID4VP/Constants/CallbackTypes.swift`

