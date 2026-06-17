# INJI-OpenID4VP-ios-swift

A Swift package for **wallet-side** processing of [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (OpenID4VP). This library validates incoming authorization requests, helps build verifiable presentations (with signing delegated to your app), and sends responses to the verifier.

## Overview

The library handles:
- Validation of incoming VP authorization requests from verifiers
- Construction of unsigned VP tokens for wallet signing
- Assembly and delivery of VP responses (including error responses) to verifiers

## Key Concepts

- **Verifier**: An entity that requests a Verifiable Presentation from the Holder (Wallet).

- **Wallet**: An application that holds Verifiable Credentials and creates Verifiable Presentations to share with Verifiers. This library provides the OpenID4VP handling for the Wallet.

- **Authorization Request**: A request sent by the Verifier to the Wallet asking for specific Verifiable Presentations. It includes credential requirements, response type, client ID, and other parameters.

- **Presentation**: A structured format containing Verifiable Credentials selected by the user in response to an Authorization Request. Created by the Wallet and sent back to the Verifier.

- **Cryptographic Holder Binding**: A mechanism that binds the Verifiable Presentation to the holder (credential owner) to prevent misuse. 

**Table of Contents**

- [OpenID4VP specification draft versions supported](#openid4vp-specification-versions-supported)
- [Supported features](#supported-features)
- [Specifications supported](#specifications-supported)
- [Functionalities](#functionalities)
- [Installation](#installation)
- [APIs](#apis)
  - [authenticateVerifier](#authenticateverifier)
  - [constructUnsignedVPToken](#constructunsignedvptoken)
  - [constructVPResponse](#constructvpresponse)
  - [sendVPResponseToVerifier](#sendvpresponsetoverifier)
  - [constructErrorInfo](#constructerrorinfo)
  - [sendErrorInfoToVerifier](#senderrorinfotoverifier)

## OpenID4VP specification versions supported

- OpenID for Verifiable Presentations - Draft 23
- OpenID for Verifiable Presentations - Version 1.0

**Spec version detection:**

- Presence of `DCQL query` or `presentation_definition`/`presentation_definition_uri` → Version 1.0 or Draft 23 respectively

## Callout

1. Removal of support for OpenID for Verifiable Presentations - Draft 21

## Supported features

### Feature Matrix by Specification Version

| Feature                                       | Draft 23  | Version 1.0 | Notes                                                                                                                                                        |
|-----------------------------------------------|:---------:|:-----------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Device Flow**                               |           |             |                                                                                                                                                              |
| — Cross device flow                           |     ✅     |      ✅      | Wallet scans QR code and passes data to this library                                                                                                         |
| — Same device flow                            |     ✅     |      ✅      | Wallet receives VP request via deeplink                                                                                                                      |
| **Client ID Prefix**                          |           |             | Equivalent to Client ID Scheme in draft 23                                                                                                                   |
| — pre-registered                              |     ✅     |      ✅      | Validated via `WalletConfig.trustedVerifiers`                                                                                                                |
| — redirect_uri                                |     ✅     |      ✅      |                                                                                                                                                              |
| — decentralized_identifier                    | ✅ (`did`) |      ✅      |                                                                                                                                                              |
| **Authorization Request Delivery**            |           |             | Per [RFC 9101](https://www.rfc-editor.org/info/rfc9101/#name-authorization-request)                                                                          |
| — By value (signed request)                   |     ✅     |      ✅      |                                                                                                                                                              |
| — By value (unsigned request)                 |     ✅     |      ✅      | Via URL-encoded parameters                                                                                                                                   |
| — By reference (request_uri)                  |     ✅     |      ✅      | Fetched via HTTP GET/POST                                                                                                                                    |
| — Request signing algorithms                  |     ✅     |      ✅      | Ed25519                                                                                                                                                      |
| **Presentation Request**                      |           |             |                                                                                                                                                              |
| — DCQL Query                                  |     ❌     |      ✅      |                                                                                                                                                              |
| — Presentation Definition                     |     ✅     |      ❌      | By value or via `presentation_definition_uri`                                                                                                                |
| — Scope parameter                             |     ❌     |      ❌      | Not implemented                                                                                                                                              |
| **VP Response Modes**                         |           |             |                                                                                                                                                              |
| — direct_post                                 |     ✅     |      ✅      |                                                                                                                                                              |
| — direct_post.jwt                             |     ✅     |      ✅      | Unsigned and Encrypted response                                                                                                                              |
| — iar-post                                    |     ✅     |      ✅      |                                                                                                                                                              |
| — iar-post.jwt                                |     ✅     |      ✅      | Unsigned and Encrypted response                                                                                                                              |
| **VP Response Type**                          |           |             |                                                                                                                                                              |
| — vp_token                                    |     ✅     |      ✅      |                                                                                                                                                              |
| — vp_token id_token                           |     ❌     |      ❌      | Not implemented                                                                                                                                              |
| — code                                        |     ❌     |      ❌      | Not implemented                                                                                                                                              |
| **Authorization Response Encryption**         |           |             | For `direct_post.jwt` and `iar-post.jwt` modes                                                                                                               |
| — Encryption algorithm (content)              |     ✅     |      ✅      | A256GCM                                                                                                                                                      |
| — Key agreement algorithm                     |     ✅     |      ✅      | ECDH-ES                                                                                                                                                      |
| **VP Token Generation**                       |           |             |                                                                                                                                                              |
| — DCQL Query-based                            |     ❌     |      ✅      |                                                                                                                                                              |
| — Presentation Definition-based               |     ✅     |      ❌      |                                                                                                                                                              |
| — Error responses                             |     ✅     |      ✅      | Any failure during VP request validation / user consent rejection / VP response preparation is prepared as Authorization Error response and sent to Verifier |
| **Supported Verifiable Presentation Formats** |           |             |                                                                                                                                                              |
| — ldp_vp                                      |     ✅     |      ✅      |                                                                                                                                                              |
| — mso_mdoc                                    |     ✅     |      ✅      |                                                                                                                                                              |
| — vc+sd-jwt / dc+sd-jwt                       |     ✅     |      ✅      |                                                                                                                                                              |

### Client ID Prefixes and Signed / Unsigned request support matrix

| Client Id Scheme                      | Supports Unsigned request             | Supports Signed request | Notes                                                                                                                                                                                                                                                                    |
|---------------------------------------|---------------------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pre-registered`                      | depends ⚖️ on pre-registered Verifier | ✅                       | When `shouldValidateClient` is true, unsigned requests are allowed only if the pre-registered verifier's `allowUnsignedRequest` is true. Otherwise, unsigned requests are always allowed. For signed requests, the trusted verifier's `jwks_uri` is used for validation. |
| `redirect_uri`                        | ✅                                     | ❌                       | Signed request is not supported, since this client ID scheme mandates unsigned Authorization Request as per the specification. [(reference)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#section-5.10.4-2.1)                                 |
| `decentralized_identifier` (or `did`) | ❌                                     | ✅                       | Only signed Authorization Requests are allowed. Requests can be sent by value or by reference, but must always be signed.                                                                                                                                                |

**Note:**
- All `By Reference` requests are fetched using HTTP GET / POST method and expected to be _**signed**_ JWT. 
  - If VP request asks for fetching the Authorization Request Object via request_uri with POST but wallet does not support POST, then GET request is initiated 
- All `By Value` requests are either _**signed**_ JWT or URL-encoded parameters (_**unsigned**_).


#### Notes on Supported response modes
1. `direct_post` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type
2. `direct_post.jwt` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. 
   - Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type. 
   - The response is encrypted using the public key provided in the client_metadata of the authorization request.
   - The created JWE's header contains the `apu` (producer info) as wallet generated nonce (with entropy 16 bytes) and `apv` (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.
   > Note: If the Authorization request includes an `mso_mdoc` format VP, it can only use the `direct_post.jwt` response mode, as required by the ISO-18013-7 specification. Other supported response mode (`direct_post`) is not applicable.
3. `iar-post` :
   - Authorization Response is constructed in unencrypted format.
   - Sample Authorization response structure of DIF Presentation Submission format:
   ```shell
    {
      "vp_token": <verifiable-presentation-token>,
      "presentation_submission": { ... }
    }
    ```
4. `iar-post.jwt` :
   - Authorization Response is constructed in encrypted format (and unsigned) using the public key provided in the client_metadata of the authorization request.
   - The created JWE's header contains the apu (producer info) as wallet generated nonce (with entropy 16 bytes) and apv (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.
   - Sample Authorization response structure:
   ```shell
    {
      "response": <encrypted data of vp_token & presentation_submission>
    }
    ```

## Functionalities

- Decode and process the Verifier’s encoded Authorization Request.
    - Authenticate the Verifier based on the identified Client ID prefix.
    - Validate the Authorization Request structure in accordance with the OpenID4VP specification.
    - Provide the validated Authorization Request (Presentation Definition or DCQL query) to the Wallet.
- Prepare the Verifiable Presentation response by requesting the Wallet to sign the required data.
- Submit the Authorization Response to the Verifier in accordance with the received presentation request.


> **Note:** Fetching Verifiable Presentations request via the [`scope`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-using-scope-parameter-to-re) parameter is not supported by this library.

## Verifiable Presentation Construction

The library SDK supports the construction of Verifiable Presentations (VPs) for the following credential formats:

* `ldp_vp`
* `dc+sd-jwt` / `vc+sd-jwt`
* `mso_mdoc`

The VP construction process applies the required cryptographic holder binding based on the credential format and the presentation request type.

---

## 1. `ldp_vp` Construction

For each shared credential with the format `ldp_vc`, the SDK constructs an `ldp_vp` presentation.

The holder key is identified using the DID (Decentralized Identifier) from the credential subject ID. This holder key is used for cryptographic holder binding in the VP proof.

### Presentation Exchange Request

For Presentation Exchange requests:

* The credential subject ID is used to identify the holder key.
* The identified holder key is used to generate the VP proof for cryptographic holder binding.

### DCQL Request

For DCQL-based requests, the `require_cryptographic_holder_binding` proof parameter determines whether holder binding is required:

* If cryptographic holder binding is required:

    * The VP is generated with a proof.
    * The proof's verification method references the holder key.
* If cryptographic holder binding is not required:

    * The credential is shared without a VP proof.

**Supported VP proof signature suite:**

* `JsonWebSignatureSuite2020`

**Supported holder key identification algorithms:**

* `RS256`
* `ES256`
* `Ed25519`
* `ES256K`

**Supported W3C Verifiable Credential Data Model:**

* Version `1.1`

---

## 2. SD-JWT VP Construction

The SDK constructs an SD-JWT Verifiable Presentation according to the IETF SD-JWT specification as profiled by OpenID4VP.

The holder key is identified using the `cnf` claim present in the credential. The identified key is used for generating the Key Binding JWT (KB-JWT) when cryptographic holder binding is required.

### Presentation Exchange Request

For Presentation Exchange requests:

* If the credential contains a `cnf` claim:

    * An SD-JWT VP with holder binding (KB-JWT) is generated.
* If the credential does not contain a `cnf` claim:

    * The SD-JWT VP is generated without holder binding.

### DCQL Request

For DCQL-based requests, the `require_cryptographic_holder_binding` proof parameter determines whether holder binding is required:

* If cryptographic holder binding is required:

    * An SD-JWT VP with KB-JWT is generated.
* If cryptographic holder binding is not required:

    * The SD-JWT VP is generated without a KB-JWT.

**Supported holder key identification mechanisms:**

* JWK-based identification:

    * `ES256`
    * *(additional algorithms to be updated)*
* Key ID (`kid`) based identification:

    * *(details to be updated)*

---

## 3. MDOC VP Construction

The SDK constructs an mdoc Verifiable Presentation according to ISO/IEC 18013-5 as referenced by OpenID4VP.

The holder key is identified using the `deviceKey` available in the `mso_mdoc` credential. This key is used for cryptographic holder binding in the presentation.

**Supported holder key identification algorithms:**

* `ES256`
* `EdDSA`

> **Note:** `vc+sd-jwt` credentials and presentations are currently supported for backward compatibility. Support for this format will be deprecated in a future release.


## INJI-OpenID4VP-ios-swift - Usage 

## Installation

1. In your Swift application, go to **File > Add Package Dependency**
2. Add the GitHub repository: `https://github.com/inji/inji-openid4vp-ios-swift.git`
3. Select the version and add the package to your target
4. Import the library to use it

## Instantiation

`OpenID4VP` is the entry point class that accepts:

- `traceabilityId`: Unique identifier for tracing requests.
- `walletConfig`: Your wallet's configuration and capabilities (optional, defaults are available).
- `jsonLdCanonicalizer`: Callback for JSON-LD canonicalization (optional, required for `ldp_vc` support).

### Wallet Configuration (`WalletConfig`)

`WalletConfig` defines the capabilities, supported protocols, cryptographic algorithms, and trusted verifier settings for the Wallet. The SDK uses this configuration to determine how Authorization Requests are validated, how Verifiers are authenticated, which credential formats can be presented, and how responses are generated.

#### WalletConfig Parameters

| Name                                        | Type                                | Required |                       Default Value                        | Description                                                                                                                 |
|---------------------------------------------|-------------------------------------|:--------:|:----------------------------------------------------------:|-----------------------------------------------------------------------------------------------------------------------------|
| `vpFormatsSupported`                        | `[VPFormatType: VPFormatSupported]` |    No    |             `ldp_vc`, `mso_mdoc`, `dc_sd_jwt`              | Defines the Verifiable Presentation formats supported by the Wallet along with their cryptographic capabilities.            |
| `clientIdPrefixesSupported`                 | `[ClientIdPrefix]`                  |    No    | `[.preRegistered, .redirectUri, .decentralizedIdentifier]` | Specifies the Client ID prefix types that the Wallet can authenticate and process.                                          |
| `requestObjectSigningAlgValuesSupported`    | `[SignatureAlgorithm]?`             |    No    |                         `[.edDsa]`                         | Signature algorithms accepted by the Wallet when validating signed Authorization Requests.                                  |
| `authorizationEncryptionAlgValuesSupported` | `[EncryptionAlgorithm]?`            |    No    |                        `[.ecdhES]`                         | Supported key management algorithms for decrypting encrypted Authorization Requests.                                        |
| `authorizationEncryptionEncValuesSupported` | `[EncryptionMethod]?`               |    No    |                        `[.a256GCM]`                        | Supported content encryption methods for encrypted Authorization Requests.                                                  |
| `responseTypesSupported`                    | `[ResponseType]`                    |    No    |                       `[.vp_token]`                        | OpenID4VP response types that can be generated by the Wallet.                                                               |
| `isPresentationDefinitionUriSupported`      | `Bool`                              |    No    |                           `true`                           | Indicates whether the Wallet supports resolving Presentation Definitions using the `presentation_definition_uri` parameter. |
| `requestUriMethodsSupported`                | `[RequestUriMethod]`                |    No    |                      `[.get, .post]`                       | Supported methods for retrieving Request Objects via `request_uri`.                                                         |
| `trustedVerifiers`                          | `[Verifier]`                        |    No    |                            `[]`                            | List of pre-configured trusted Verifiers known to the Wallet.                                                               |
| `validatePreRegisteredVerifier`             | `Bool`                              |    No    |                           `true`                           | Indicates whether pre-registered Verifiers should be validated against the configured trusted Verifier list.                |

#### Verifier Parameters

| Name                   | Type       | Required | Default Value | Description                                                                                        |
|------------------------|------------|:--------:|:-------------:|----------------------------------------------------------------------------------------------------|
| `clientId`             | `String`   |   Yes    |      N/A      | Unique identifier of the Verifier.                                                                 |
| `responseUris`         | `[String]` |   Yes    |      N/A      | List of permitted response endpoints to which the Wallet can send Authorization Responses.         |
| `jwksUri`              | `String?`  |    No    |     `nil`     | URI containing the Verifier's public keys used for signature verification and trust establishment. |
| `allowUnsignedRequest` | `Bool`     |    No    |    `false`    | Indicates whether unsigned Authorization Requests are accepted from the Verifier.                  |

#### Example

```swift
let walletConfig = WalletConfig(
    isPresentationDefinitionUriSupported: true,
    vpFormatsSupported: [...],
    clientIdPrefixesSupported: [
        .preRegistered,
        .redirectUri,
        .decentralizedIdentifier
    ],
    requestObjectSigningAlgValuesSupported: [.edDsa],
    authorizationEncryptionAlgValuesSupported: [.ecdhES],
    authorizationEncryptionEncValuesSupported: [.a256GCM],
    responseTypesSupported: [.vp_token],
    trustedVerifiers: [...]
)
```

### Wallet Metadata Generation

When the Verifier uses the `request_uri` flow with the `POST` method, the SDK automatically derives Wallet Metadata from the configured `WalletConfig` and sends it to the Verifier. This allows the Verifier to generate an Authorization Request that is compatible with the Wallet's declared capabilities.

| Wallet Metadata Property                                                                                                             | Derived From                                                                                                             |
|--------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `vp_formats_supported`                                                                                                               | `vpFormatsSupported`                                                                                                     |
| `client_id_prefixes_supported` for OpenID4VP Spec Version 1.0 (or) `client_id_schemes_supported` for OpenID4VP Spec Version Draft 23 | `clientIdPrefixesSupported`                                                                                              |
| `request_object_signing_alg_values_supported`                                                                                        | `requestObjectSigningAlgValuesSupported`                                                                                 |
| `authorization_encryption_alg_values_supported`                                                                                      | `authorizationEncryptionAlgValuesSupported`                                                                              |
| `authorization_encryption_enc_values_supported`                                                                                      | `authorizationEncryptionEncValuesSupported`                                                                              |
| `response_types_supported`                                                                                                           | `responseTypesSupported`                                                                                                 |
| `presentation_definition_uri_supported`                                                                                              | `isPresentationDefinitionUriSupported` (Only applicable while communicating to Verifier following Spev version draft 23) |


#### Wallet Metadata Communication

When the Verifier uses the `request_uri` flow with the `POST` method, the SDK automatically derives Wallet Metadata from the configured `WalletConfig` and includes it in the request made to the Verifier.

This allows the Verifier to understand the Wallet's capabilities before generating the final Authorization Request. The communicated Wallet Metadata typically includes:

| Wallet Metadata Property                      | Derived From                                |
|-----------------------------------------------|---------------------------------------------|
| Supported VP formats                          | `vpFormatsSupported`                        |
| Supported Client ID prefixes                  | `clientIdPrefixesSupported`                 |
| Supported request object signing algorithms   | `requestObjectSigningAlgValuesSupported`    |
| Supported authorization encryption algorithms | `authorizationEncryptionAlgValuesSupported` |
| Supported authorization encryption methods    | `authorizationEncryptionEncValuesSupported` |
| Supported response types                      | `responseTypesSupported`                    |
| Presentation Definition URI support           | `isPresentationDefinitionUriSupported`      |

As a result, the Verifier can tailor the Authorization Request to the capabilities advertised by the Wallet, ensuring compatibility between the Wallet and Verifier implementations.

## 1. Resolve and Validate Authorization Request URI

The Verifier prepares an OpenID4VP Authorization Request and shares it with the Wallet, either through a deep link or a QR code. Once the Wallet receives the Authorization Request, invoke the `authenticateVerifier` API from the Wallet library to resolve the request, authenticate the Verifier, and perform validation of the Authorization Request in accordance with the OpenID4VP specification.

Upon successful validation, the API returns a fully resolved Authorization Request containing the presentation requirements (Presentation Definition or DCQL query), which can then be used by the Wallet to prepare the Verifiable Presentation response. 

### `authenticateVerifier` 

This method:
- Receives and validates the Verifier's encoded Authorization Request
- Validates the VP request and client verification
- Extracts the clientId and verifies it against the wallet's trusted verifiers
- If the request contains `request_uri`, fetches the Authorization Request from that URI
- Validates the incoming request with wallet capabilities
- Returns the validated `AuthorizationRequest` object

**Client validation:**
- For `pre-registered` clients: validates against `WalletConfig.trustedVerifiers`
- Can be disabled by setting `**validatePreRegisteredVerifier**` to `false` in wallet config

```swift
let authorizationRequest: AuthorizationRequest = try await openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest: encodedAuthorizationRequest,
    shouldValidateClient: true
)
```

###### Parameters

| Name                           | Type             | Required | Default Value | Description                                          |
|--------------------------------|------------------|:---------|:--------------|------------------------------------------------------|
| urlEncodedAuthorizationRequest | String           | Yes      | N/A           | URL Encoded authorization request from the Verifier. |


###### Example usage

```swift
 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: "openid4vp://authorize?client_id=...."
            )
```

###### Exceptions

- `DecodingException`: Issue while decoding the Authorization Request
- `InvalidQueryParams`: Missing or invalid query parameters, or both/neither of `presentation_definition` and `presentation_definition_uri` present
- `MissingInput`: Required parameters not present in the request
- `InvalidInput`: Required parameter values are empty
- `JWTVerification`: Error extracting public key, kid, or signature verification failure
- `InvalidData`: Request client_id/response_uri don't match trusted verifiers, unsupported response_mode, or missing client_metadata
- `UnsupportedPublicKeyType`: Public key type is not `publicKeyMultibase`
- `PublicKeyResolutionFailed`: Error extracting public key from verification method
- `InvalidVerifier`: Request client_id/response_uri don't match any trusted verifiers

**Note:** The library automatically sends error notifications to the Verifier's response_uri when applicable.

### `authenticateVerifier` - Additional Overload

In addition to accepting a URL-encoded Authorization Request, `authenticateVerifier` also provides an overload that accepts an already parsed Authorization Request as a dictionary.

This overload performs the same processing and validations as the URL-encoded variant, including:

* Verifier authentication and client validation
* Resolution of `request_uri` requests
* Authorization Request validation
* Validation against Wallet capabilities
* Trusted Verifier verification
* Returning a validated `AuthorizationRequest` object

###### Example Usage

```swift
let authorizationRequest: AuthorizationRequest = try await openID4VP.authenticateVerifier(
    authorizationRequest: [
        "client_id": "example-verifier",
        "response_type": "vp_token",
        "presentation_definition": [...]
    ]
)
```

###### Parameters

| Name                   | Type            | Required | Default Value | Description                                               |
|------------------------|-----------------|:--------:|:-------------:|-----------------------------------------------------------|
| `authorizationRequest` | `[String: Any]` |   Yes    |      N/A      | Parsed Authorization Request represented as a dictionary. |

###### Returns

| Type                   | Description                                         |
|------------------------|-----------------------------------------------------|
| `AuthorizationRequest` | Fully validated and resolved Authorization Request. |

###### Exceptions

This overload throws the same exceptions as the URL-encoded variant.

## 2. User Selection of Credentials and Consent

After the Wallet successfully authenticates the Verifier and validates the OpenID4VP Authorization Request, the next step is to determine which credentials available in the Wallet satisfy the presentation requirements requested by the Verifier.  The Wallet should evaluate its stored credentials against the requested Presentation Definition or DCQL Query, present the matching credentials to the Wallet consumer, and obtain explicit consent before proceeding with presentation generation.

The SDK provides helper utilities for DCQL-based credential matching, allowing Wallet implementations to identify eligible credentials before displaying them to the user for selection.

> **Note:** The SDK currently provides credential matching support only for DCQL-based Authorization Requests through `DCQLHelper`. For Authorization Requests containing a Presentation Definition, credential matching and constraint evaluation must be implemented by the Wallet application based on its credential storage and presentation logic.

### DCQL Credential Matching

For Authorization Requests containing a DCQL query, the SDK provides the `DCQLHelper` utility to evaluate Wallet credentials against the requested constraints. The helper performs credential matching based on the supplied DCQL query and returns all credentials that satisfy the requested conditions.

You can obtain the DCQL query from a validated `AuthorizationDcqlRequest` and use it to identify matching credentials before prompting the user for selection and consent.

### `DCQLHelper`

`DCQLHelper` provides functionality for evaluating Wallet credentials against a DCQL query.

#### Parameters

| Name             | Type                      | Required | Default Value | Description                                                                                                                                                                                              |
|------------------|---------------------------|:--------:|:-------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jsonLdExpander` | `JsonLdExpanderCallback?` |    No    |     `nil`     | Optional callback used to expand JSON-LD credentials before DCQL evaluation. This is required when the Wallet credentials are JSON-LD based as credential matching depends on expanded JSON-LD contexts. |
|

#### Example Usage

```swift
import OpenID4VP

let dcqlHelper = DCQLHelper(jsonLdExpander: jsonLdExpanderCallback)
```

### `getMatchingCredentials`

Evaluates a collection of Wallet credentials against a DCQL query and returns the credentials that satisfy the requested constraints. This method should typically be invoked after receiving a validated `AuthorizationDcqlRequest` and before presenting credentials to the Wallet consumer for selection.

#### Method Signature

```swift
public func getMatchingCredentials(
    inputCredentials: [Credential],
    dcqlQuery: DCQLQuery
) async throws -> MatchingCredentialsResult
```

### Usage in Credential Matching

The Wallet passes its available credentials as input to credential matching:

```swift
let matchingResult = try await dcqlHelper.getMatchingCredentials(
    inputCredentials: walletAvailableCredentials,
    dcqlQuery: dcqlQuery
)
```

The SDK evaluates each `Credential` against the DCQL query constraints and returns the credentials that satisfy the requested requirements.

#### Parameters

| Name               | Type           | Required | Default Value | Description                                                                                        |
|--------------------|----------------|:--------:|:-------------:|----------------------------------------------------------------------------------------------------|
| `inputCredentials` | `[Credential]` |   Yes    |      N/A      | Collection of credentials available in the Wallet that should be evaluated against the DCQL query. |
| `dcqlQuery`        | `DCQLQuery`    |   Yes    |      N/A      | DCQL query extracted from the validated Authorization Request.                                     |

#### Returns

| Type                        | Description                                                                                                            |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------|
| `MatchingCredentialsResult` | Contains the credentials that satisfy the DCQL query and any associated matching metadata generated during evaluation. |

#### Example Usage with Authorization Request

```swift
guard let dcqlRequest = authorizationRequest as? AuthorizationDcqlRequest else {
    // Handle Presentation Definition related matching credentials
}

let dcqlHelper = DCQLHelper(jsonLdExpander: jsonLdExpanderCallback)

let matchingResult = try await dcqlHelper.getMatchingCredentials(
    inputCredentials: walletAvailableCredentials,
    dcqlQuery: dcqlRequest.dcqlQuery
)
```

#### Credential Structure

`Credential` represents a Verifiable Credential stored in the Wallet and is used as an input when evaluating presentation requirements, such as DCQL queries. The Wallet provides its available credentials in this format to the SDK helper methods (`DCQLHelper.getMatchingCredentials`) to determine which credentials satisfy the Verifier's request.

A `Credential` contains the credential format, the credential payload, and a unique identifier that allows the Wallet to track and manage the credential.

##### Parameters

| Name           | Type         | Required | Default Value | Description                                                                                                                                                                                |
|----------------|--------------|:--------:|:-------------:|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `format`       | `FormatType` |   Yes    |      N/A      | Specifies the format of the credential. The format determines how the credential is represented and processed during presentation. Examples include `ldp_vc`, `mso_mdoc`, and `dc_sd_jwt`. |
| `data`         | `AnyCodable` |   Yes    |      N/A      | Contains the credential payload in a format-specific representation. The Wallet should provide the complete credential data required for evaluation and presentation generation.           |
| `credentialId` | `String`     |   Yes    |      N/A      | Unique identifier assigned to the credential by the Wallet. This identifier is used to reference the credential during matching.                                                           |

##### Credential Format Handling

The `data` field is format-specific and should contain the credential in its native representation:

| Credential Format | `data` Representation                         | Additional Requirements                                                                      |
|-------------------|-----------------------------------------------|----------------------------------------------------------------------------------------------|
| `ldp_vc`          | JSON-LD Verifiable Credential object          | Requires JSON-LD processing support when matching depends on expanded JSON-LD contexts.      |
| `mso_mdoc`        | Mobile Security Object (mDoc) credential data | Should contain the data required for ISO/IEC 18013-5 presentation processing.                |
| `dc_sd_jwt`       | SD-JWT credential representation              | Should contain the full SD-JWT credential data required for selective disclosure processing. |


### Wallet Responsibilities

* Maintaining the credential store.
* Providing credentials in the expected Credential structure.
* Ensuring credential data is complete and valid for the declared format.
* Handling user selection and consent before sharing credentials.
* Providing selected credentials for Verifiable Presentation construction.

Once the Wallet consumer has selected the credentials and granted consent, the selected credentials can be used to construct the Verifiable Presentation and continue the OpenID4VP presentation flow.

## 3. Construction of a Verifiable Presentation and Submission to the Verifier

Once the user has selected the credentials and provided consent for sharing them, the Wallet constructs a Authorization Response and submits it to the Verifier.

The VP construction process begins with preparing the unsigned data that must be signed by the Wallet. This step is common across all Authorization Response construction flows and is performed using the `constructUnsignedVPToken` method.

After the unsigned data has been signed, the SDK supports two different approaches:

1. **Authorization Response Construction and Submission** - `sendVPResponseToVerifier`

    * The signed data is provided back to the SDK.
    * The SDK constructs the Verifiable Presentation and generates the Authorization Response.
    * The SDK then submits the Authorization Response to the Verifier.

2. **Authorization Response Construction Only** - `constructVPResponse`

    * The signed data is provided back to the SDK.
    * The SDK constructs the Verifiable Presentation and generates the Authorization Response.
    * The Authorization Response is returned to the library consumer, who is responsible for submitting it to the Verifier.

### Prepare Data for VP Construction — `constructUnsignedVPToken`

This method generates a flattened list of unsigned data (`UnsignedVPToken`) from the selected Verifiable Credentials. By providing all required signing information upfront, this method simplifies the signing workflow for each VP token.

```swift
let unsignedVPTokens: [UnsignedVPToken] = try await openID4VP.constructUnsignedVPToken(
    selectedCredentials: [String: [Credential]]
)
```

#### Error Handling: 

Any failure encountered during this phase results in an OAuth error response being returned to the Verifier.

```json
{
  "error": "server_error",
  "error_description": "The wallet encountered an internal error while preparing the presentation."
}
```

#### Request Parameters

| Name                | Type                   | Required | Description                                                                                                                                                         |
|---------------------|------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| selectedCredentials | [String: [Credential]] | Yes      | Map of credential query IDs or input descriptor IDs to credential lists. For understanding Credential structure refer [Credential Structure](#credential-structure) |


> **Note:**
>
> * When using selectively disclosable credentials, only the claims selected for disclosure to the Verifier should be included in the credentials passed to the SDK for VP construction.
> * The Wallet must ensure that a valid credential is provided for each credential query ID (or input descriptor ID) that it intends to satisfy as part of the presentation.


#### Response Parameters

Each `UnsignedVPToken` in the returned array contains:

| Property           | Type       | Description                                                                                                                                                                                                                                                             |
|--------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| format             | FormatType | Credential format (ldp_vc, mso_mdoc, vc+sd-jwt, dc+sd-jwt)                                                                                                                                                                                                              |
| holderKeyReference | String     | Reference to holder's key. The identified holder key reference can be used by the Consumer of the Library to locate the corresponding private key and sign the VP token payload. For more details refer [Holder Key Identification feature](#holder-key-identification) |
| signatureAlgorithm | String     | Signature algorithm to be used (e.g., ES256)                                                                                                                                                                                                                            |
| dataToSign         | Data       | Payload data that must be signed                                                                                                                                                                                                                                        |

#### Example usage

```swift
let unsignedVPTokens: [UnsignedVPToken] = try await openID4VP.constructUnsignedVPToken(
    selectedCredentials: [
        "input_descriptor_id_1": [
           Credential(...)
        ],
    ]
)

// The wallet can now iterate through unsignedVPTokens and sign each one
let signingResults = unsignedVPTokens.map { token in
    let signature = try signData(
        token.dataToSign,
        keyReference: token.holderKeyReference,
        algorithm: token.signatureAlgorithm
    )
    return VPTokenSigningResult(signedData: signature)
}
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if:
    - Provided verifiable credentials list is empty
    - No mapping found for a specific credential format
    - Invalid credential structure


### Prepare Authorization Response — `constructVPResponse`

This method constructs the Authorization Response according to the `response_type` and `response_mode` specified in the Verifiable Presentation request. It embeds the generated Verifiable Presentation(s) into the response and returns the complete authorization response payload to the Wallet. The generated authorization response is returned to the caller for further handling.


```swift
let vpResponse: [String: Any] = openID4VP.constructVPResponse(
    vpTokenSigningResults: vpTokenSigningResults
)
```

#### Error Handling:

Any failure encountered during this phase results in an OAuth error response being returned to the Verifier.

```json
{
  "error": "server_error",
  "error_description": "The wallet encountered an internal error while preparing the authorization response."
}
```

#### Parameters

| Name                  | Type                   | Required | Description                                                                |
|-----------------------|------------------------|----------|----------------------------------------------------------------------------|
| vpTokenSigningResults | [VPTokenSigningResult] | Yes      | Ordered list of signing results matching `constructUnsignedVPToken` output |

#### Response Parameters

| Type           | Description                                                                                           |
|----------------|-------------------------------------------------------------------------------------------------------|
| [String : Any] | Dictionary containing the constructed Authorization response as per response type and `response_mode` |

#### Example usage

```swift
let vpResponse: [String: Any] = openID4VP.constructVPResponse(
    vpTokenSigningResults: vpTokenSigningResults
)
```

#### Exceptions

- `JsonEncodingFailed`: Issue serializing the vp_token or presentation_submission
- `InvalidData`: Unsupported response_type in the authorization request

### Prepare and submit Authorization Response to Verifier - `sendVPResponseToVerifier`

This method generates an Authorization Response in accordance with the `response_type` and `response_mode` defined in the Verifiable Presentation request, embeds the Verifiable Presentation(s), and submits the resulting response to the Verifier.

```swift
let response: VerifierResponse = try await openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults: vpTokenSigningResults
)
```

#### Error Handling:

Any failure encountered during this phase results in an OAuth error response being returned to the Verifier.

```json
{
  "error": "server_error",
  "error_description": "The wallet encountered an internal error while preparing the authorization response."
}
```

###### Parameters

| Name                  | Type                   | Required | Description                                                         |
|-----------------------|------------------------|----------|---------------------------------------------------------------------|
| vpTokenSigningResults | [VPTokenSigningResult] | Yes      | Ordered list of signing results matching `constructUnsignedVPToken` |

#### Response - VerifierResponse Structure

| Property         | Type          | Description                                      |
|------------------|---------------|--------------------------------------------------|
| statusCode       | Int           | HTTP status code from the Verifier               |
| redirectUri      | String        | URI to redirect user after response submission   |
| additionalParams | [String: Any] | Additional response parameters from the Verifier |
| headers          | [String: Any] | Response headers from the Verifier               |

###### Example usage

```swift
let response: VerifierResponse = try await openID4VP.sendVPResponseToVerifier(
    vpTokenSigningResults: vpTokenSigningResults
)
```

###### Exceptions

- `JsonEncodingFailed`: Issue serializing vp_token or presentation_submission
- `UnsupportedTypeDecoding`: Error decoding unsupported types
- `InterruptedIOException`: Connection timeout
- `NetworkRequestFailed`: HTTP POST request failure
- `InvalidData`: Unsupported response_type


### ConstructErrorInfo 

Constructs an OAuth/OpenID4VP error response dictionary from an exception.

```swift
let errorResponse: [String: Any] = openID4VP.constructErrorInfo(exception: error)
```

## 4. Dispatch Error to Verifier

### `sendErrorInfoToVerifier`

This method is used to send errors to the Verifier for errors that need to be handled by the library consumer during the overall OpenID4VP flow.

The library automatically handles and dispatches errors that occur internally during:

* OpenID4VP request validation
* Authorization Response construction

Only errors that require intervention or decision-making by the Wallet or library consumer should be passed explicitly to this method.

This method:

* Sends the provided error information to the Verifier.
* Returns the response received from the Verifier.

For the structure of the returned response, refer to [VerifierResponse structure](#verifierresponse-structure).

```swift
// Example: User declined to share credentials
let verifierResponse: VerifierResponse = try await openID4VP.sendErrorInfoToVerifier(
    error: AccessDenied(
        message: "User did not give consent to share the requested Credentials.",
        className: "WalletApp"
    )
)
```

###### Exceptions

* `ErrorDispatchFailure`: Raised when the error response cannot be successfully sent to the Verifier.


## Minimal working Swift example

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
            urlEncodedAuthorizationRequest: encodedAuthorizationRequest,
            shouldValidateClient: true
        )

        var selectedCredentials: [String: [Credential]] = [:]
            

        if let vpRequest = validatedVPRequest as? AuthorizationDcqlRequest {
            // DCQL flow
            let dcqlHelper = DCQLHelper(jsonLdExpander: jsonLdExpanderCallback)
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
        
        let signingResults = try unsignedVpTokens.map { token in
            let signature = try signData(
                token.dataToSign,
                keyReference: token.holderKeyReference,
                algorithm: token.signatureAlgorithm
            )
            return VPTokenSigningResult(signedData: signature)
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

# Migration Guides

Refer [migration_guide](./doc/migation-guide) for library upgrading

# Architecture decisions

Architecture decisions are documented in the [INJI OpenID4VP ADR directory](https://github.com/inji/inji-openid4vp/tree/master/doc).

# Also available in

This library is also available in the following languages
- [kotlin](https://github.com/inji/inji-openid4vp/tree/master/kotlin)

[//]: # (## TODOs)

[//]: # ()
[//]: # (1. 1 VP per ldp_vc construction - no grouping of ldp_vcs for VP)

[//]: # (2. handling of VP for ldp_vc - supported only for one subject focussed Credential - multiple subject credentials are not supported currently)
[//]: # (/)DCQL flow responsibilty
[//]: # (3. Document one-flow-at-a-time instance usage, or make Swift state actor-isolated / guarded.)

# Limitations

1. **`scope` parameter support**
   The `scope` parameter defined in the specification is currently not supported.

2. **Single flow instance usage**
   A single library instance supports only one OpenID4VP flow execution at a time. Concurrent flows using the same instance are not supported.

3. **`constructUnsignedVPToken` input validation**
   The `selectedCredentials` provided to `constructUnsignedVPToken` are expected to comply with the OpenID4VP specification requirements. The SDK does not perform additional validations on the provided credential selection.

   For example, in the case of DCQL-based requests, if a credential query ID does not support multiple credentials but the Wallet provides multiple credentials for that query ID, the SDK does not validate or reject this condition. Ensuring that the provided credential selection is valid according to the presentation request is the responsibility of the Wallet.

