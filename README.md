# INJI-OpenID4VP-ios-swift

inji-openid4vp-ios-swift is an implementation of OpenID for Verifiable Presentations written in swift

**Table of Contents**

- [Supported features](#supported-features)
- [Specifications supported](#specifications-supported)
- [Functionalities](#functionalities)
- [Installation](#installation)
- [APIs](#apis)
  - [authenticateVerifier](#authenticateverifier)
  - [constructUnsignedVPToken](#constructUnsignedVPToken)
  - [shareVerifiablePresentation](#shareverifiablepresentation)
  - [sendErrorToVerifier](#senderrortoverifier)


## Supported features

| Feature                                                    | Supported values                                                                                                                                                                                                                                                                                                                                                   |
|------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Device flow                                                | cross device flow, Same device flow                                                                                                                                                                                                                                                                                                                                |
| Client id scheme                                           | `pre-registered`, `redirect_uri`, `did`                                                                                                                                                                                                                                                                                                                            |
| Signed authorization request verification algorithms       | Ed25519                                                                                                                                                                                                                                                                                                                                                            |
| Obtaining authorization request                            | By value, By reference ( via `request_uri` method) <br> _[Note: Authorization request by value is not supported for the did client ID scheme, as it requires a signed request. Instead, a Request URI should be used to fetch the signed authorization request ([reference](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html#section-3.2))]_ |
| Obtaining presentation definition in authorization request | By value, By reference (via `presentation_definition_uri`)                                                                                                                                                                                                                                                                                                         |
| Presentation Request                                       | Presentation Exchange                                                                                                                                                                                                                                                                                                                                              |
| Authorization Response mode                                | `direct_post`, `direct_post.jwt` (with encrypted & unsigned responses)                                                                                                                                                                                                                                                                                             |
| Authorization Response content encryption algorithms       | `A256GCM`                                                                                                                                                                                                                                                                                                                                                          |
| Authorization Response key encryption algorithms           | `ECDH-ES`                                                                                                                                                                                                                                                                                                                                                          |
| Authorization Response type                                | `vp_token`                                                                                                                                                                                                                                                                                                                                                         |
| Supported Credential formats                               | `ldp_vc`, `mso_mdoc`                                                                                                                                                                                                                                                                                                                                               |

#### Notes on Supported response modes
1. `direct_post` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type
2. `direct_post.jwt` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. 
   - Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type. 
   - The response is encrypted using the public key provided in the client_metadata of the authorization request.
   - The created JWE's header contains the `apu` (producer info) as wallet generated nonce (with entropy 16 bytes) and `apv` (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.

## Specifications supported
- The implementation follows OpenID for Verifiable Presentations - draft 23. [Specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html).
- Below are the fields we expect in the authorization request based on the client id scheme,
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
- VC format supported is Ldp Vc as of now.

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

## APIs

### authenticateVerifier
 - Receives a list of trusted verifiers & Verifier's encoded Authorization request from consumer app(mobile wallet).
 - Optionally it also receives wallet metadata to be shared with the verifier.
 - Takes an optional boolean to toggle the client validation.
 - Decodes and parse the request, extracts the clientId and verifies it against trusted verifier's list clientId.
 - If the data contains request_uri and request_uri_method as post, then the wallet metadata is shared in the request body while making an api call to request_uri for fetching authorization request.
 - The library also validates the incoming authorization request with the wallet metadata
 - Returns the validated Authorization request object

**Notes**
- Wallet can send the entire metadata, library will customize it as per authorization request client_id_scheme. Eg - in case pre-registered, library modifies wallet metadata to be sent without request object signing info properties as specified in the specification.

#### WalletMetadata Parameters

| Parameter                                 | Type                        | Required   | Default Value      | Description                                                                                      |
|-------------------------------------------|-----------------------------|------------|--------------------|--------------------------------------------------------------------------------------------------|
| presentationDefinitionURISupported        | Bool                        | No         | true               | Indicates whether the wallet supports `presentation_definition_uri`.                             |
| vpFormatsSupported                        | [String: VPFormatSupported] | Yes        | N/A                | A dictionary specifying the supported verifiable presentation formats and their algorithms.      |
| clientIdSchemesSupported                  | [String]                    | No         | ["pre-registered"] | A list of supported client ID schemes.                                                           |
| requestObjectSigningAlgValuesSupported    | [String]?                   | No         | nil                | A list of supported algorithms for signing request objects.                                      |
| authorizationEncryptionAlgValuesSupported | [String]?                   | No         | nil                | A list of supported algorithms for encrypting authorization responses.                           |
| authorizationEncryptionEncValuesSupported | [String]?                   | No         | nil                | A list of supported encryption methods for authorization responses.                              |




```swift
    let authorizationRequest : AuthorizationRequest = try authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifierJSON: [Verifier],walletMetadata: WalletMetadata, shouldValidateClient: Bool)
```

###### Parameters

| Name                           | Type             | Description                                                                      |
|--------------------------------|------------------|----------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest | String           | URL Encoded authorization request.                                               |
| trustedVerifierJSON            | [Verifier]       | Array of verifiers to verify the client id of the verifier.                      |
| walletMetadata                 | WalletMetadata?  | Optional WalletMetadata to be shared with Verifier                               |
| shouldValidateClient           | Bool             | Optional Boolean to toggle client validation for pre-registered client id scheme |


###### Example usage

```swift

 let walletMetadata = WalletMetadata(
    presentationDefinitionURISupported: true,
    vpFormatsSupported: ["ldp_vc": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018", "Ed25519Signature2020"])],
    clientIdSchemesSupported: ["pre-registered", "redirect_uri", "did"],
    requestObjectSigningAlgValuesSupported: ["EdDSA"],
    authorizationEncryptionAlgValuesSupported: ["ECDH-ES"],
    authorizationEncryptionEncValuesSupported: ["A256GCM"]
)

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
5. InvalidVerifier exception is thrown if the received request client_id & response_uri are not matching with any of the trusted verifiers
6. JWTVerification exception is thrown if there is any error in extracting public key, kid or signature verification failure.
7. InvalidData exception is thrown if 
   - `response_mode` is not supported
   - For `direct_post.jwt` response mode
     - client_metadata is not available
     - unable to find the public key JWK from the `jwks` of `client_metadata` as per the provided algorithm in `client_metadata`

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### constructUnsignedVPToken
- Receives a dictionary of input_descriptor id & list of verifiable credentials for each input_descriptor that are selected by the end-user.
- Creates a vp_token without proof using received input_descriptor IDs and verifiable credentials, then returns its string representation to consumer app(mobile wallet) for signing it.

```swift
    let unsignedVPTokens = try openID4VP.constructUnsignedVPToken(credentialsMap: [String: [FormatType: Array<Any>]])
```

###### Parameters

| Name           | Type                               | Description                                                                                                                                    |
|----------------|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| credentialsMap | [String: [FormatType: Array<Any>]] | A Map which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials |

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

| Name                  | Type                               | Description                                                                                                                                                   |
|-----------------------|------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | [FormatType: VPTokenSigningResult] | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |


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
2. InterruptedIOException is thrown if the connection is timed out when network call is made.
3. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
4. InvalidData exception is thrown if the response_type in the authorization request is not supported


This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### sendErrorToVerifier
- Receives an exception and sends it's message to the Verifier via a HTTP POST request.

```
 openID4VP.sendErrorToVerifier(error: Error)
```

###### Parameters

| Name  | Type  | Description                   | Sample                                                                            |
|-------|-------|-------------------------------|-----------------------------------------------------------------------------------|
| error | Error | Contains the exception object | `AuthorizationConsent.consentRejectedError(message: "User rejected the consent")` |

###### Example usage

```swift
await openID4VP.sendErrorToVerifier(error: AuthorizationConsent.consentRejectedError(message: "User rejected the consent"))
```

###### Exceptions

1. InterruptedIOException is thrown if the connection is timed out when network call is made.
2. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.

## Architecture decisions

Architecture decisions are noted as ADRs [here](https://github.com/mosip/inji-openid4vp/tree/master/doc).

## Also available in

This library is also available in the following languages
- [kotlin](https://github.com/mosip/inji-openid4vp/tree/master/kotlin)