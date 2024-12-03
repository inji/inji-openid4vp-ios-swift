# INJI-OpenID4Vp-ios-swift
- Implementation of OpenID4VP protocols in Swift.

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
 - Decodes and parse the request, extracts the clientId and verifies it against trusted verifier's list clientId.
 - Returns the Authentication response which contains validated Presentation Definition of the request.



```
    let response = try authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifierJSON: [Verifier])
```

###### Parameters

| Name                         | Type       | Description                                                 | Sample                                              |
|------------------------------|------------|-------------------------------------------------------------|-----------------------------------------------------|
| encodedAuthorizationRequest | String     | Base64 Encoded authorization request.                       | `"T1BFTklENFZQOi8vYXV0"`                            |
| trustedVerifierJSON          | [Verifier] | Array of verifiers to verify the client id of the verifier. | `Verifier(clientId: String, responseUris: [String])` |


###### Exceptions

1. DecodingException is thrown when there is and issue while decoding the Authorization Request
2. InvalidQueryParams exception is thrown if
    - query params are not present in the Request
    - there is a issue while extracting the params
    - both presentation_definition and presentation_definition_uri are present in Request
    - both presentation_definition and presentation_definition_uri are not present in Request
3. MissingInput exception is thrown if any of required params are not present in Request
4. InvalidInput exception is thrown if any of required params value is empty
5. InvalidVerifierClientID exception is thrown if the received request client_id & response_uri are not matching with any of the trusted verifiers

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### constructVerifiablePresentation
- Receives a dictionary of input_descriptor id & list of verifiable credentials for each input_descriptor that are selected by the end-user.
- Creates a vp_token without proof using received input_descriptor IDs and verifiable credentials, then returns its string representation to consumer app(mobile wallet) for signing it.

```
    let response = try openID4VP.constructVerifiablePresentation(credentialsMap: [String: [String]])
```

###### Parameters

| Name                | Type             | Description                                                                                              | Sample                                            |
|---------------------|------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| credentialsMap      | [String: [String]] | Contains the input descriptor id as key and corresponding matching Verifiable Credentials as array of string. | `["bank_input":["VC1","VC2"]]`                            |


###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### shareVerifiablePresentation
- This function constructs a vp_token with proof using received VPResponseMetadata, then sends it and the presentation_submission to the Verifier via a HTTP POST request.
- Returns the response back to the consumer app(mobile app) saying whether it has received the shared Verifiable Credentials or not.

```
    let response = try await openID4VP.shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata)
```

###### Parameters

| Name                | Type             | Description                                                                                               | Sample                                            |
|---------------------|------------------|-----------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| vpResponseMetadata      | VPResponseMetadata | Contains a VPResponseMetadata which has proof details such as  jws, signatureAlgorithm, publicKey, domain | `VPResponseMetadata(jws: "jws", signatureAlgorithm: "signatureAlgoType", publicKey: "publicKey", domain: "domain")`                            |


###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InterruptedIOException is thrown if the connection is timed out when network call is made.
3. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### sendErrorToVerifier
- Receives an exception and sends it's message to the Verifier via a HTTP POST request.

```
 openID4VP.sendErrorToVerifier(error: Error)
```

###### Parameters

| Name  | Type   | Description                   | Sample                                                                                |
|-------|--------|-------------------------------|---------------------------------------------------------------------------------------|
| error | Error  | Contains the exception object | `AuthorizationConsent.consentRejectedError(message: "User rejected the consent")` |


###### Exceptions

1. InterruptedIOException is thrown if the connection is timed out when network call is made.
2. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
