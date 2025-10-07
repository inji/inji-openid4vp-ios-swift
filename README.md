# INJI-OpenID4VP-ios-swift

inji-openid4vp-ios-swift is an implementation of OpenID for Verifiable Presentations written in swift

**Table of Contents**

- [OpenID4VP specification draft versions supported](#openid4vp-specification-draft-versions-supported)
- [Supported features](#supported-features)
- [Specifications supported](#specifications-supported)
- [Functionalities](#functionalities)
- [Installation](#installation)
- [APIs](#apis)
  - [authenticateVerifier](#authenticateverifier)
  - [constructUnsignedVPToken](#constructUnsignedVPToken)
  - [shareVerifiablePresentation](#shareverifiablepresentation)
  - [sendErrorToVerifier](#senderrortoverifier)

## OpenID4VP specification draft versions supported

- OpenID for Verifiable Presentations - draft 21
- OpenID for Verifiable Presentations - draft 23

## Supported features

| Feature                                                    | Supported values                                                       |
|------------------------------------------------------------|------------------------------------------------------------------------|
| Device flow                                                | cross device flow, Same device flow                                    |
| Client id scheme                                           | `pre-registered`, `redirect_uri`, `did`                                |
| Signed authorization request verification algorithms       | Ed25519                                                                |
| Obtaining authorization request                            | By value, By reference ( via `request_uri` method)                     |
| Obtaining presentation definition in authorization request | By value, By reference (via `presentation_definition_uri`)             |
| Presentation Request                                       | Presentation Exchange                                                  |
| Authorization Response mode                                | `direct_post`, `direct_post.jwt` (with encrypted & unsigned responses) |
| Authorization Response content encryption algorithms       | `A256GCM`                                                              |
| Authorization Response key encryption algorithms           | `ECDH-ES`                                                              |
| Authorization Response type                                | `vp_token`                                                             |
| Supported Credential formats                               | `ldp_vc`, `mso_mdoc`, `vc+sdjwt`, `dc+sd-jwt`                          |

#### Client ID Schemes and obtaining authorization request matrix

| Client Id Scheme | Supports By Value | Supports By Reference | Notes                                                                                                                                                                                                                                                                                            |
|------------------|-------------------|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pre-registered` | ✅                 | ✅                     | -                                                                                                                                                                                                                                                                                                |
| `redirect_uri`   | ✅                 | ❌                     | Authorization request by reference is not supported, since this client ID scheme mandates unsigned Authorization Request. [(reference)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#section-5.10.4-2.1)                                                              |
| `did`            | ❌                 | ✅                     | Authorization request by value is not supported for the did client ID scheme, as it requires a signed request. Instead, a Request URI should be used to fetch the signed authorization request ([reference](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html#section-3.2)) |


#### Notes on Supported response modes
1. `direct_post` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type
2. `direct_post.jwt` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. 
   - Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type. 
   - The response is encrypted using the public key provided in the client_metadata of the authorization request.
   - The created JWE's header contains the `apu` (producer info) as wallet generated nonce (with entropy 16 bytes) and `apv` (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.
   > Note: If the Authorization request includes an `mso_mdoc` format VP, it can only use the `direct_post.jwt` response mode, as required by the ISO-18013-7 specification. Other supported response mode (`direct_post`) is not applicable.

## Specifications supported
- The implementation follows OpenID for Verifiable Presentations - draft 21 and draft23 .[Specification-21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html) [Specification-23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html).
- The library validates the client_id and client_id_scheme parameters in the authorization request according to the relevant specification.
- If the client_id_scheme parameter is included in the authorization request, the request is treated as conforming to Draft 21, and validation is performed accordingly.
- If the client_id_scheme parameter is not included, the request is interpreted as following Draft 23, and validation is applied based on that specification.

- Below are the fields we expect in the authorization request based on the client id scheme as part of draft 21,
  - Client_id_scheme is **_pre-registered_**
    * client_id
    * client_id_scheme
    * presentation_definition/presentation_definition_uri
    * response_type
    * response_mode
    * nonce
    * state
    * response_uri
    * client_metadata (Optional)

  - Client_id_scheme is **_redirect_uri_**
    * client_id
    * client_id_scheme
    * presentation_definition/presentation_definition_uri
    * response_type
    * nonce
    * state
    * redirect_uri
    * client_metadata (Optional)
    
  - **_Request Uri_** is also supported as part of this version.
    - When request_uri is passed as part of the authorization request, below are the fields we expect in the authorization request,
        * client_id
        * client_id_scheme
        * request_uri
        * request_uri_method
    
- Below are the fields we expect in the authorization request based on the client id scheme as part of draft 23,
  - Client_id_scheme is **_pre-registered_**
    * client_id
    * presentation_definition/presentation_definition_uri
    * response_type
    * response_mode
    * nonce
    * state
    * response_uri
    * client_metadata (Optional)

  - Client_id_scheme is **_redirect_uri_**
    * client_id
    * presentation_definition/presentation_definition_uri
    * response_type
    * nonce
    * state
    * redirect_uri
    * client_metadata (Optional)
    
  - **_Request Uri_** is also supported as part of this version.
  - When request_uri is passed as part of the authorization request, below are the fields we expect in the authorization request,
     * client_id
     * request_uri
     * request_uri_method
   
  - The request uri can return either a jwt token/encoded if it is a jwt the signature is verified as mentioned in the specification.
  - The client id and client id scheme from the authorization request and the client id and client id scheme received from the response of the request uri should be same.

**Note** : The pre-registered client id scheme validation can be toggled on/off based on the optional boolean which you can pass to the authenticateVerifier methods shouldValidateClient parameter. This is false by default.
## Functionalities
- Decode and parse the Verifier's encoded Authorization Request received from the Wallet.
- Authenticates the Verifier using the received clientId and returns the valid Presentation Definition to the Wallet.
- Receives the list of verifiable credentials(VC's) from the Wallet which are selected by the end user based on the credentials requested as part of Verifier Authorization request.
- Constructs the verifiable presentation and send it to wallet for generating Json Web Signature (JWS).
- Receives the signed Verifiable presentation and sends a POST request with generated vp_token and presentation_submission to the Verifier response_uri endpoint.


  **Note** : Fetching Verifiable Credentials by passing [Scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-using-scope-parameter-to-re) param in Authorization Request is not supported by this library.

## Installation
- In your swift application go to file > add package dependency > add the  https://github.com/mosip/inji-openid4vp-ios-swift.git in git search bar> add package
- Import the library and use

## 🚨 Breaking Changes

From Version release-0.4.x onward:

### API contract changes
This library has undergone some changes in its API contract. 

#### 1. Instantiation of OpenID4VP
- The OpenID4VP class is now initialized with `traceabilityId` and `walletMetadata` parameters.
  - traceabilityId: Used to track the traceability of the requests and responses.
  - walletMetadata: Metadata which wallet supports, such that client-id-scheme support, vp format support, proof type support, etc. (See [walletMetadata construction](#walletmetadata-construction) below for details)

```swift
let openID4VP = OpenID4VP(traceabilityId: "trace-id", walletMetadata: WalletMetadata)
```

#### 2. Construction of WalletMetadata
- The WalletMetadata construction has now been simplified. You can create a WalletMetadata object with the required parameters exposed as constants.
- In detail,
- `WalletMetadata` is now a struct that contains the following properties:
  - `presentationDefinitionURISupported`: Bool
  - `vpFormatsSupported`: [String: VPFormatSupported]
  - `clientIdSchemesSupported`: [ClientIdScheme]
  - `requestObjectSigningAlgValuesSupported`: [RequestSigningAlgorithm]?
  - `authorizationEncryptionAlgValuesSupported`: [KeyManagementAlgorithm]?
  - `authorizationEncryptionEncValuesSupported`: [ContentEncryptionAlgorithm]?

```swift
let walletMetadata = try WalletMetadata(presentationDefinitionURISupported: true,
                                        vpFormatsSupported: [
                                            .ldp_vc: VPFormatSupported(
                                                algValuesSupported: ["Ed25519Signature2018", "Ed25519Signature2020"]
                                            ),
                                            .mso_mdoc: VPFormatSupported(
                                                algValuesSupported: ["ES256"]
                                            )
                                        ],
                                        clientIdSchemesSupported: [.preRegistered, .redirectUri, .did],
                                        requestObjectSigningAlgValuesSupported: [.edDsa],
                                        authorizationEncryptionAlgValuesSupported: [.ecdhEs],
                                        authorizationEncryptionEncValuesSupported: [.A256GCM])
```

3. The `shouldValidateClient` parameter in `authenticateVerifier` now defaults to true.
- If your integration previously relied on it being false, you must now explicitly pass false to preserve the old behavior.
- Example (updated usage)

```swift
 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri,
                trustedVerifierJSON: trustedVerifiers),
                walletMetadata: walletMetadata,
                shouldValidateClient: false // explicitly set to false if you want to skip client validation
            )
```

## Construction of OpenID4VP instance

- The OpenID4VP class is initialized with `traceabilityId` and `walletMetadata` parameters.

```swift
let openID4VP = OpenID4VP(traceabilityId: "trace-id", walletMetadata: WalletMetadata)
```

###### Parameters
| Name           | Type            | Required | Default Value                                                            | Description                                                                                                                                                                                                     |
|----------------|-----------------|:---------|:-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| traceabilityId | String          | Yes      | N/A                                                                      | Unique identifier for tracking requests and responses.                                                                                                                                                          |
| walletMetadata | WalletMetadata  | No       | nil                                                                      | Metadata which wallet supports, such that client-id-scheme support, vp format support, proof type support, etc. (See [below](#walletmetadata-construction) for more details on construction of wallet metadata) |

### WalletMetadata construction
- The WalletMetadata is a struct that contains metadata about the wallet's capabilities and supported features.
- It is used to inform the Verifier about the wallet's capabilities when processing authorization requests.
- The WalletMetadata will be sent to the verifier while making a POST request to the `request_uri` endpoint if the authorization request contains `request_uri` and `request_uri_method` as `post`.

```swift
let walletMetadata = try WalletMetadata(presentationDefinitionURISupported: true,
                                        vpFormatsSupported: [
                                            .ldp_vc: VPFormatSupported(
                                                algValuesSupported: ["Ed25519Signature2018", "Ed25519Signature2020"]
                                            ),
                                            .mso_mdoc: VPFormatSupported(
                                                algValuesSupported: ["ES256"]
                                            )
                                        ],
                                        clientIdSchemesSupported: [.preRegistered, .redirectUri, .did],
                                        requestObjectSigningAlgValuesSupported: [.edDsa],
                                        authorizationEncryptionAlgValuesSupported: [.ecdhEs],
                                        authorizationEncryptionEncValuesSupported: [.A256GCM])
```

#### Parameters

| Parameter                                 | Type                            | Required | Default Value                  | Description                                                                                 |
|-------------------------------------------|---------------------------------|----------|--------------------------------|---------------------------------------------------------------------------------------------|
| presentationDefinitionURISupported        | Bool                            | No       | true                           | Indicates whether the wallet supports `presentation_definition_uri`.                        |
| vpFormatsSupported                        | [FormatType: VPFormatSupported] | Yes      | N/A                            | A dictionary specifying the supported verifiable presentation formats and their algorithms. |
| clientIdSchemesSupported                  | [ClientIdScheme]                | No       | [ClientIdScheme.preRegistered] | A list of supported client ID schemes.                                                      |
| requestObjectSigningAlgValuesSupported    | [RequestSigningAlgorithm]?      | No       | nil                            | A list of supported algorithms for signing request objects.                                 |
| authorizationEncryptionAlgValuesSupported | [KeyManagementAlgorithm]?       | No       | nil                            | A list of supported algorithms for encrypting authorization responses.                      |
| authorizationEncryptionEncValuesSupported | [ContentEncryptionAlgorithm]?   | No       | nil                            | A list of supported encryption methods for authorization responses.                         |

**Notes**
- Wallet can send the entire metadata, library will customize it as per authorization request client_id_scheme. Eg - in case pre-registered, library modifies wallet metadata to be sent without request object signing info properties as specified in the specification.

## APIs

### authenticateVerifier
 - Receives a list of trusted verifiers & Verifier's encoded Authorization request from consumer app(mobile wallet).
 - Takes an optional boolean to toggle the client validation.
 - Decodes and parse the request, extracts the clientId and verifies it against trusted verifier's list clientId.
 - If the data contains request_uri and request_uri_method as post, then the wallet metadata is shared in the request body while making an api call to request_uri for fetching authorization request.
 - The library also validates the incoming authorization request with the wallet metadata
 - Returns the validated Authorization request object


```swift
    let authorizationRequest : AuthorizationRequest = try authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifierJSON: [Verifier], shouldValidateClient: Bool)
```

###### Parameters

| Name                           | Type             | Required | Default Value | Description                                                                      |
|--------------------------------|------------------|:---------|:--------------|----------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest | String           | Yes      | N/A           | URL Encoded authorization request.                                               |
| trustedVerifierJSON            | [Verifier]       | Yes      | N/A           | Array of verifiers to verify the client id of the verifier.                      |
| walletMetadata                 | WalletMetadata?  | Yes      | N/A           | Optional WalletMetadata to be shared with Verifier                               |
| shouldValidateClient           | Bool             | No       | true          | Optional Boolean to toggle client validation for pre-registered client id scheme |


###### Example usage

```swift
 let trustedVerifiers: [Verifier] = [Verifier(clientId: "https://mock-verifier.com", responseUris:["https://mock-verifier.com/response"]

 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri,
                trustedVerifierJSON: trustedVerifiers),
                walletMetadata: walletMetadata,
                shouldValidateClient: true
            )
```


###### Exceptions

1. DecodingException is thrown when there is and issue while decoding the Authorization Request
2. InvalidQueryParams exception is thrown if
    - query params are not present in the Request
    - there is a issue while extracting the params
    - both presentation_definition and presentation_definition_uri are present in Request
    - both presentation_definition and presentation_definition_uri are not present in Request
3. MissingInput exception is thrown if any of required params are not present in Request
4. InvalidInput exception is thrown if any of required params value is empty
5. JWTVerification exception is thrown if there is any error in extracting public key, kid or signature verification failure.
6. InvalidData exception is thrown if 
   - the received request client_id & response_uri are not matching with any of the trusted verifiers
   - `response_mode` is not supported
   - For `direct_post.jwt` response mode
     - client_metadata is not available
     - unable to find the public key JWK from the `jwks` of `client_metadata` as per the provided algorithm in `client_metadata`
   - `publicKeyMultibase` is null or empty 
7. UnsupportedPublicKeyType exception is thrown when the public key type is not `publicKeyMultibase`.
8. PublicKeyResolutionFailed exception is thrown when there are any errors in extracting the public key from verification method
9. InvalidVerifier exception is thrown if the received request client_iD & response_uri are not matching with any of the trusted verifiers
     

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### constructUnsignedVPToken
- Receives a dictionary of input_descriptor id & list of verifiable credentials for each input_descriptor that are selected by the end-user.
- Creates a vp_token without proof using received input_descriptor IDs and verifiable credentials, then returns its string representation to consumer app(mobile wallet) for signing it.

```swift
    let unsignedVPTokens = try openID4VP.constructUnsignedVPToken(credentialsMap: [String: [FormatType: Array<Any>]])
```

###### Parameters

| Name           | Type                               | Required | Default Value | Description                                                                                                                                    |
|----------------|------------------------------------|:--------:|:--------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| credentialsMap | [String: [FormatType: Array<Any>]] |   Yes    | N/A           | A Map which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials |

###### Example usage

```swift
let unsignedVPTokens: [FormatType: UnsignedVPToken] = try openID4VP.constructUnsignedVPToken(
    credentialsMap: [
        "input_descriptor_id": [
            FormatType.ldp_vc.rawValue: [["id": "uuid-1234-1234", //....]],
            FormatType.mso_mdoc.rawValue: ["<base64-encoded-cbor-encoded-credential>"]
        ]
    ]
)
```

###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if provided verifiable credentials list is empty

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### shareVerifiablePresentation
- This function constructs a vp_token with proof using received VPTokenSigningResult, then sends it and the presentation_submission to the Verifier via a HTTP POST request.
- Returns the response back to the consumer app(mobile app) saying whether it has received the shared Verifiable Credentials or not.

```swift
    let response = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: [FormatType:VPTokenSigningResult])
```

###### Parameters

| Name                  | Type                               | Required | Default Value | Description                                                                                                                                                   |
|-----------------------|------------------------------------|:---------|:--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | [FormatType: VPTokenSigningResult] | Yes      | N/A           | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |


###### Example usage

```swift
let ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws : createJWS(unsignedLdpVPToken),
    signatureAlgorithm : "RsaSignature2018",
    publicKey : "<publicKey>",
    domain : "<domain>"
)

let mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication: [
        "<docType>": DeviceAuthentication(
            signature: createSignature(unsignedMdocVPToken.docTypeToDeviceAuthenticationBytes("<docType>")), 
            algorithm: "<mdocAuthenticationAlgorithm>",
        )
    ]
  )
let vpTokenSigningResults : [FormatType: VPTokenSigningResult] = [FormatType.ldp_vc : ldpVPTokenSigningResult, FormatType.mso_mdoc: mdocVPTokenSigningResult]
val response : String = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults : vpTokenSigningResults)
```

###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. UnsupportedTypeDecoding exception is thrown when there is any issue in decoding the unsupported type.
3. InterruptedIOException is thrown if the connection is timed out when network call is made.
4. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
5. InvalidData exception is thrown if the response_type in the authorization request is not supported


This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### sendErrorResponseToVerifier

- Receives an exception and sends it's message to the Verifier via an HTTP POST request to the Verifier's response_uri endpoint.
- Returns back the response body received from the Verifier.

```swift
// Example: The user declines to share the requested credentials. In this case, Verifier needs to be informed about the scenario.
// So call the sendErrorResponseToVerifier method with appropriate exception message to notify the Verifier.

let verifierResponse: String = openID4VP.sendErrorResponseToVerifier(
        AccessDenied(
            message = "User did not give consent to share the requested Credentials with the Verifier.",
            className = this.className
        )
)
```
###### Exceptions

1. ErrorDispatchFailure is thrown if any issue occurs while sending the Authorization Error response to the Verifier.

### sendErrorToVerifier (deprecated, use sendErrorResponseToVerifier instead)
- Receives an exception and sends it's message to the Verifier via a HTTP POST request.

```
 openID4VP.sendErrorToVerifier(error: Error)
```

###### Parameters

| Name  | Type  | Description                   | Required | Default Value | Sample                                                                            |
|-------|-------|-------------------------------|:---------|:--------------|-----------------------------------------------------------------------------------|
| error | Error | Contains the exception object | Yes      | N/A           | `AuthorizationConsent.consentRejectedError(message: "User rejected the consent")` |

###### Example usage

```swift
await openID4VP.sendErrorToVerifier(error: AuthorizationConsent.consentRejectedError(message: "User rejected the consent"))
```

###### Exceptions

1. ErrorDispatchFailure is thrown if any issue occurs while sending the Authorization Error response to the Verifier.

###### Exception Handling Enhancement

- The library has been enhanced to handle exceptions more gracefully. Library is throwing `OpenID4VPException` now which gives both Error Code, Message and optional state to the consumer app. The `state` value is extracted from the authorization request and is included in the error response only if it is present and non-empty. This allows the consumer app to handle exceptions more effectively and provide better user experience.

## 🚨 Deprecation Notice

The following methods are deprecated and will be removed in future releases. Please migrate to the suggested alternatives.

| Method Name         | Description                               | Deprecated Since | Suggested Alternative                                       |
|---------------------|-------------------------------------------|------------------|-------------------------------------------------------------|
| sendErrorToVerifier | Sends Authorization error to the verifier | 0.6.0            | [sendErrorResponseToVerifier](#sendErrorResponseToVerifier) |

## Architecture decisions

Architecture decisions are noted as ADRs [here](https://github.com/mosip/inji-openid4vp/tree/master/doc).

## Also available in

This library is also available in the following languages
- [kotlin](https://github.com/mosip/inji-openid4vp/tree/master/kotlin)
