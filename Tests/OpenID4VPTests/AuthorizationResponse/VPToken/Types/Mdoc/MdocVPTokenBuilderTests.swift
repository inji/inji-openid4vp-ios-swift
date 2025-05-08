import XCTest
@testable import OpenID4VP
import SwiftCBOR

final class MdocVPTokenBuilderTests: XCTestCase {
    let unsignedToken = UnsignedMdocVPToken(docTypeToDeviceAuthenticationBytes: ["org.iso.18013.5.1.mDL": "bytes"])
    
    func testBuildsVPTokenSuccessfullyWithValidInput() {
        let metadata = MdocVpTokenSigningResult(deviceAuthenticationBytesSigned: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "validSignature", algorithm: "ES256")])
        let credentials = [sampleMdoc]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, credentials: credentials)
        
        XCTAssertNoThrowAndVerify(try builder.build()) { vpToken in
            XCTAssertTrue(vpToken is MdocVPToken, "vpToken should be of type MdocVPToken")
            XCTAssertNotNil((vpToken as! MdocVPToken).value)
            let mdocVPToken: (MdocVPToken) = (vpToken as! MdocVPToken)
            let decodedToken = try? decodeCBOR(base64EncodedInput: mdocVPToken.value)
            
            // Verify keys - status, version, documents, documents -> deviceSigned is available in the token as its attached to the Verifiable Presentation by the builder
            XCTAssertEqual(decodedToken?["status"], CBOR.unsignedInt(0))
            XCTAssertEqual(decodedToken?["version"], CBOR.utf8String("1.0"))
            XCTAssertTrue(decodedToken?["documents"] is CBOR.ArrayLiteralElement, "documents should be an array")
            XCTAssertNotNil(decodedToken?["documents"]?[0]?["deviceSigned"], "Token should contain deviceSigned key")
        }
    }
    
    func testThrowsErrorWhenCredentialIsInvalidCBOR() {
        let metadata = MdocVpTokenSigningResult(deviceAuthenticationBytesSigned: ["docType1": DeviceAuthentication(signature: "validSignature", algorithm: "RS256")])
        let credentials = ["invalidCBOR"]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Verifiable Credential: Error while decoding credential")
        }
    }
    
    func testThrowsErrorWhenDocTypeIsMissingInCredential() {
        let metadata = MdocVpTokenSigningResult(deviceAuthenticationBytesSigned: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "validSignature", algorithm: "ES256")])
        let mdocWithoutDocType = "b1d4cGMzTjFaWEpUYVdkdVpXU2lhbWx6YzNWbGNrRjFkR2lFUTZFQkpxRVlJVmtDQURDQ0Fmd3dnZ0dqQWhRRjJ6YmVnZFdxMVhITG1kclZaWklPUlNfZWZEQUtCZ2dxaGtqT1BRUURBakNCZ0RFTE1Ba0dBMVVFQmhNQ1NVNHhDekFKQmdOVkJBZ01Ba3RCTVJJd0VBWURWUVFIREFsQ1FVNUhRVXhQVWtVeERqQU1CZ05WQkFvTUJVbEpTVlJDTVF3d0NnWURWUVFMREFORVExTXhFREFPQmdOVkJBTU1CME5GVWxSSlJsa3hJREFlQmdrcWhraUc5dzBCQ1FFV0VXMXZjMmx3Y1dGQVoyMWhhV3d1WTI5dE1CNFhEVEkxTURJeE1qRXlNekUxTjFvWERUSTJNREl4TWpFeU16RTFOMW93Z1lBeEN6QUpCZ05WQkFZVEFrbE9NUXN3Q1FZRFZRUUlEQUpMUVRFU01CQUdBMVVFQnd3SlFrRk9SMEZNVDFKRk1RNHdEQVlEVlFRS0RBVkpTVWxVUWpFTU1Bb0dBMVVFQ3d3RFJFTlRNUkF3RGdZRFZRUUREQWREUlZKVVNVWlpNU0F3SGdZSktvWklodmNOQVFrQkZoRnRiM05wY0hGaFFHZHRZV2xzTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJBY1pYcnNnTlNBQnpnOW9fZE5LdTZTMnBYdUozaGdZbFgxNjJFeDU2SVVHREpaUF9JbFJDckVRUEhaU1NsNTNEd2xwTDRpSGlzQVNxRmFSUWlYQXRxa3dDZ1lJS29aSXpqMEVBd0lEUndBd1JBSWdHSTZCNjNRY2NKUTRCODRoUmpSR2xSVVJKNVNTTlR1Zjc0dy1uRTh6cVJBQ0lBM2RpaUQzVkNBNUc2am9HZVRTWC1YeDc5c2hoRHJDbVVIdWozTGs1dUwxV1FKUjJCaFpBa3ltWjNabGNuTnBiMjVqTVM0d2IyUnBaMlZ6ZEVGc1oyOXlhWFJvYldkVFNFRXRNalUyWjJSdlkxUjVjR1YxYjNKbkxtbHpieTR4T0RBeE15NDFMakV1YlVSTWJIWmhiSFZsUkdsblpYTjBjNkZ4YjNKbkxtbHpieTR4T0RBeE15NDFMakdvQWxnZ29ZVzVzYjZFU0ZvczY1SmRjckdscFc0RHpieXllMDJHenhZcGRiMTRsVDRHV0NCT0ttYnltdlp4OW1sWC16cTdmS1B6TTNCUEJwNWU4S0xEX0c0azFHc01Td05ZSUZsS1ZCWHRyRVB5REhwQ3AtRV9NVDJSVENkdVo2WXZvODRrakFqOS1GNzlBVmdnZVlER1RmeDh3N1N6MmhJUXZrWjFRaHRyWHNraERqWmtTX2NnTjZIUDE4b0VXQ0JlWmxrVzI5aXFVQkx4QUZsT2ZIcno1cVhpb1hLS2FveUVFWUk5Nll5S3Z3QllJSWxERjR1VDFEM01MR1BzTEwta1ZCUDBTSHl4QVljQVZmOVNMWUxVSlVVZ0IxZ2dGdUkwY21WMVd3U0pHdjVWeEk1YTdEc202ZklxcjJNZUlEQm1ZaklsWjBvRldDQTg4a09vOEtOR3RDcGwyWEg1Q1hNY2dvRTZEX2ZhZzl4am1Qb0xVY3BncEcxa1pYWnBZMlZMWlhsSmJtWnZvV2xrWlhacFkyVkxaWG1rQVFJZ0FTRllJQ1QxeXk1endVVFBXRVNTOEtSZ0ZMcmtNRm5XTWJPa05QOXZablJsR3BwdklsZ2dCbDdxb05MZmp0Zl9yNk01NDNuYWxSVUdBdC1QTmk4dTVRdmhPZjNNUUt4c2RtRnNhV1JwZEhsSmJtWnZvMlp6YVdkdVpXVEFkREl3TWpVdE1EUXRNVFJVTURjNk1qRTZNamRhYVhaaGJHbGtSbkp2YmNCME1qQXlOUzB3TkMweE5GUXdOem95TVRveU4xcHFkbUZzYVdSVmJuUnBiTUIwTWpBeU55MHdOQzB4TkZRd056b3lNVG95TjFwWVFNcTJzWVM2Z095b29oNHdmTGxTTjZhQU13VHo1aWotZ2wzd2hNd3ZXMjg1VWVhc2MxcU5tc0ZVbkU1LXlBcGhNMXhGOEYyY01NUFdJMENrYmlSSUdGQnFibUZ0WlZOd1lXTmxjNkZ4YjNKbkxtbHpieTR4T0RBeE15NDFMakdJMkJoWVdLUm9aR2xuWlhOMFNVUUNabkpoYm1SdmJWQnRoU3kxdm1waHFwb01ZUmU5WjBQbmNXVnNaVzFsYm5SSlpHVnVkR2xtYVdWeWFtbHpjM1ZsWDJSaGRHVnNaV3hsYldWdWRGWmhiSFZsYWpJd01qVXRNRFF0TVRUWUdGaFpwR2hrYVdkbGMzUkpSQVptY21GdVpHOXRVTnlYaFhPWmptaGVpRnl6WWZoc2wwWnhaV3hsYldWdWRFbGtaVzUwYVdacFpYSnJaWGh3YVhKNVgyUmhkR1ZzWld4bGJXVnVkRlpoYkhWbGFqSXdNekF0TURRdE1UVFlHRmlmcEdoa2FXZGxjM1JKUkFObWNtRnVaRzl0VUNDLXY3QVJBTEoyVkZjWXd3OUFiTWh4Wld4bGJXVnVkRWxrWlc1MGFXWnBaWEp5WkhKcGRtbHVaMTl3Y21sMmFXeGxaMlZ6YkdWc1pXMWxiblJXWVd4MVpYaEllMmx6YzNWbFgyUmhkR1U5TWpBeU5TMHdOQzB4TkN3Z2RtVm9hV05zWlY5allYUmxaMjl5ZVY5amIyUmxQVUVzSUdWNGNHbHllVjlrWVhSbFBUSXdNekF0TURRdE1UUjkyQmhZWGFSb1pHbG5aWE4wU1VRQlpuSmhibVJ2YlZEam9Zal84UkJaNjItODVpWlYzNzF2Y1dWc1pXMWxiblJKWkdWdWRHbG1hV1Z5YjJSdlkzVnRaVzUwWDI1MWJXSmxjbXhsYkdWdFpXNTBWbUZzZFdWcU9USTJNVFE0TVRBeU5OZ1lXRldrYUdScFoyVnpkRWxFQkdaeVlXNWtiMjFRZzdpV2NOYlotYjlTMkQzdTNBdjJZbkZsYkdWdFpXNTBTV1JsYm5ScFptbGxjbTlwYzNOMWFXNW5YMk52ZFc1MGNubHNaV3hsYldWdWRGWmhiSFZsWWtsTzJCaFlXS1JvWkdsblpYTjBTVVFBWm5KaGJtUnZiVkFGZzF6TUZxMW9MWXhIaWliMFVDZVljV1ZzWlcxbGJuUkpaR1Z1ZEdsbWFXVnlhbUpwY25Sb1gyUmhkR1ZzWld4bGJXVnVkRlpoYkhWbGFqRTVPVFF0TVRFdE1EYllHRmhVcEdoa2FXZGxjM1JKUkFkbWNtRnVaRzl0VUVsWm0xYmRVN00xR2xjclFQSl9jdE54Wld4bGJXVnVkRWxrWlc1MGFXWnBaWEpxWjJsMlpXNWZibUZ0Wld4bGJHVnRaVzUwVm1Gc2RXVm1TbTl6WlhCbzJCaFlWYVJvWkdsblpYTjBTVVFGWm5KaGJtUnZiVkJfTkh0ZG1Ya1dMUHFWblNneXBHR1djV1ZzWlcxbGJuUkpaR1Z1ZEdsbWFXVnlhMlpoYldsc2VWOXVZVzFsYkdWc1pXMWxiblJXWVd4MVpXWkJaMkYwYUdF"
        let credentials = [mdocWithoutDocType]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Verifiable Credential: docType not available in credential")
        }
    }
    
    func testThrowsErrorWhenDeviceAuthenticationBytesAreMissing() {
        let metadata = MdocVpTokenSigningResult(deviceAuthenticationBytesSigned: ["docType1": DeviceAuthentication(signature: "validSignature", algorithm: "RS256")])
        let credentials = [sampleMdoc]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error.localizedDescription, "Missing Input: mdocVPResponeMetadata->deviceAuthenticationBytesSigned->DeviceAuthentication param is required")
        }
    }
    
    func testThrowsErrorWhenMetadataValidationFails() {
        let metadata = MdocVpTokenSigningResult(deviceAuthenticationBytesSigned: ["docType1": DeviceAuthentication(signature: "", algorithm: "ES256")])
        let credentials = [sampleMdoc]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: DeviceAuthentication->signature value cannot be empty or null")
        }
    }
}
