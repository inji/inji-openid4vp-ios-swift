let testVerifierList:  [[String: Any]]  = [
    [
        "client_id": "https://injiverify.dev2.mosip.net",
        "response_uris": [
            "https://injiverify.qa-inji.mosip.net/redirect",
            "https://injiverify.dev2.mosip.net/redirect"
        ]
    ],
    [
        "client_id": "https://injiverify.dev1.mosip.net",
        "response_uris": [
            "https://injiverify.qa-inji.mosip.net/redirect",
            "https://injiverify.dev1.mosip.net/redirect"
        ]
    ]
]

// base64 -> client_id_scheme = redirect_uri
let testValidBase64EncodedVpRequestWithRedirectUri = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXJlZGlyZWN0X3VyaSZyZWRpcmVjdF91cmk9aHR0cHM6Ly9pbmppdmVyaWZ5LmRldjIubW9zaXAubmV0JnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaWQiOiIxMjMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJiYW5raW5nX2lucHV0XzEiLCJmb3JtYXQiOiB7ImxkcF92YyI6IHsicHJvb2ZfdHlwZSI6IFsiRWQyNTUxOVNpZ25hdHVyZTIwMTgiXX19LCJuYW1lIjoiQmFuayBBY2NvdW50IEluZm9ybWF0aW9uIiwicHVycG9zZSI6ImhpaWlpIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQuY3JlZGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yICAjIHZlcmlmaWNhdGlvbiBwdXJwb3NlICMgZm9yIGFueXRoaW5nIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX0seyJwYXRoIjpbIiQudmMuY3JlZGVudGlhbCIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuYWNjb3VudFsqXS5yb3V0ZSIsIiQuYWNjb3VudFsqXS5yb3V0ZSJdLCJwdXJwb3NlIjoiV2UgY2FuIHVzZSBmb3IgdmVyaWZpY2F0aW9uIHB1cnBvc2UiLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk/JCJ9fV19fV19JnJlc3BvbnNlX3R5cGU9dnBfdG9rZW4mbm9uY2U9VmJSUkIvTFR4TGlYbVZOWnV5TU84QT09JnN0YXRlPSttUlFlMWQ2cEJvSnFGNkFiMjhrbGc9PSZjbGllbnRfbWV0YWRhdGE9eyJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJFQ0RILUVTIiwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTI1NkdDTSIsInZwX2Zvcm1hdHMiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRWREU0EiXX0sImxkcF92cCI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiRWQyNTUxOVNpZ25hdHVyZTIwMjAiLCJSc2FTaWduYXR1cmUyMDE4Il19fX0="

// base64 -> client_id_scheme = redirect_uri, with response uri and response mode
let testVpRequestWithRedirectUriAndResponseUriResponseMode = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXJlZGlyZWN0X3VyaSZyZXNwb25zZV91cmk9aHR0cHM6Ly9pbmppdmVyaWZ5LmRldjIubW9zaXAubmV0JnJlc3BvbnNlX21vZGU9ZGlyZWN0X3Bvc3QmcHJlc2VudGF0aW9uX2RlZmluaXRpb249eyJpZCI6IjEyMyIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6ImJhbmtpbmdfaW5wdXRfMSIsImZvcm1hdCI6IHsibGRwX3ZjIjogeyJwcm9vZl90eXBlIjogWyJFZDI1NTE5U2lnbmF0dXJlMjAxOCJdfX0sIm5hbWUiOiJCYW5rIEFjY291bnQgSW5mb3JtYXRpb24iLCJwdXJwb3NlIjoiaGlpaWkiLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5jcmVkZSJdLCJwdXJwb3NlIjoiV2UgY2FuIHVzZSBmb3IgICMgdmVyaWZpY2F0aW9uIHB1cnBvc2UgIyBmb3IgYW55dGhpbmciLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk/JCJ9fSx7InBhdGgiOlsiJC52Yy5jcmVkZW50aWFsIiwiJC52Yy5jcmVkZW50aWFsU3ViamVjdC5hY2NvdW50WypdLnJvdXRlIiwiJC5hY2NvdW50WypdLnJvdXRlIl0sInB1cnBvc2UiOiJXZSBjYW4gdXNlIGZvciB2ZXJpZmljYXRpb24gcHVycG9zZSIsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwicGF0dGVybiI6Il5bMC05XXs5fXxeKFthLXpBLVpdKXs0fShbYS16QS1aXSl7Mn0oWzAtOWEtekEtWl0pezJ9KFswLTlhLXpBLVpdezN9KT8kIn19XX19XX0mcmVzcG9uc2VfdHlwZT12cF90b2tlbiZub25jZT1WYlJSQi9MVHhMaVhtVk5adXlNTzhBPT0mc3RhdGU9K21SUWUxZDZwQm9KcUY2QWIyOGtsZz09JmNsaWVudF9tZXRhZGF0YT17ImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIiwidnBfZm9ybWF0cyI6eyJtc29fbWRvYyI6eyJhbGciOlsiRVMyNTYiLCJFZERTQSJdfSwibGRwX3ZwIjp7InByb29mX3R5cGUiOlsiRWQyNTUxOVNpZ25hdHVyZTIwMTgiLCJFZDI1NTE5U2lnbmF0dXJlMjAyMCIsIlJzYVNpZ25hdHVyZTIwMTgiXX19fQ=="

// base64 -> client_id_scheme = redirect_uri, and not equal to client id
let testVpRequestWithRedirectUriAndClientIdNotEqual = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5tb3NpcC5uZXQmY2xpZW50X2lkX3NjaGVtZT1yZWRpcmVjdF91cmkmcmVkaXJlY3RfdXJpPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZwcmVzZW50YXRpb25fZGVmaW5pdGlvbj17ImlkIjoiMTIzIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiYmFua2luZ19pbnB1dF8xIiwiZm9ybWF0IjogeyJsZHBfdmMiOiB7InByb29mX3R5cGUiOiBbIkVkMjU1MTlTaWduYXR1cmUyMDE4Il19fSwibmFtZSI6IkJhbmsgQWNjb3VudCBJbmZvcm1hdGlvbiIsInB1cnBvc2UiOiJoaWlpaSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLmNyZWRlIl0sInB1cnBvc2UiOiJXZSBjYW4gdXNlIGZvciAgIyB2ZXJpZmljYXRpb24gcHVycG9zZSAjIGZvciBhbnl0aGluZyIsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwicGF0dGVybiI6Il5bMC05XXs5fXxeKFthLXpBLVpdKXs0fShbYS16QS1aXSl7Mn0oWzAtOWEtekEtWl0pezJ9KFswLTlhLXpBLVpdezN9KT8kIn19LHsicGF0aCI6WyIkLnZjLmNyZWRlbnRpYWwiLCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmFjY291bnRbKl0ucm91dGUiLCIkLmFjY291bnRbKl0ucm91dGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yIHZlcmlmaWNhdGlvbiBwdXJwb3NlIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX1dfX1dfSZyZXNwb25zZV90eXBlPXZwX3Rva2VuJm5vbmNlPVZiUlJCL0xUeExpWG1WTlp1eU1POEE9PSZzdGF0ZT0rbVJRZTFkNnBCb0pxRjZBYjI4a2xnPT0mY2xpZW50X21ldGFkYXRhPXsiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkEyNTZHQ00iLCJ2cF9mb3JtYXRzIjp7Im1zb19tZG9jIjp7ImFsZyI6WyJFUzI1NiIsIkVkRFNBIl19LCJsZHBfdnAiOnsicHJvb2ZfdHlwZSI6WyJFZDI1NTE5U2lnbmF0dXJlMjAxOCIsIkVkMjU1MTlTaWduYXR1cmUyMDIwIiwiUnNhU2lnbmF0dXJlMjAxOCJdfX19"

// base64 -> client_id_scheme = pre-registered
let testValidBase64EncodedVpRequestWithResponseUri = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXByZS1yZWdpc3RlcmVkJnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaWQiOiIxMjMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJiYW5raW5nX2lucHV0XzEiLCJmb3JtYXQiOiB7ImxkcF92YyI6IHsicHJvb2ZfdHlwZSI6IFsiRWQyNTUxOVNpZ25hdHVyZTIwMTgiXX19LCJuYW1lIjoiQmFuayBBY2NvdW50IEluZm9ybWF0aW9uIiwicHVycG9zZSI6ImhpaWlpIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQuY3JlZGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yICAjIHZlcmlmaWNhdGlvbiBwdXJwb3NlICMgZm9yIGFueXRoaW5nIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX0seyJwYXRoIjpbIiQudmMuY3JlZGVudGlhbCIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuYWNjb3VudFsqXS5yb3V0ZSIsIiQuYWNjb3VudFsqXS5yb3V0ZSJdLCJwdXJwb3NlIjoiV2UgY2FuIHVzZSBmb3IgdmVyaWZpY2F0aW9uIHB1cnBvc2UiLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk/JCJ9fV19fV19JnJlc3BvbnNlX3R5cGU9dnBfdG9rZW4mcmVzcG9uc2VfbW9kZT1kaXJlY3RfcG9zdCZub25jZT1WYlJSQi9MVHhMaVhtVk5adXlNTzhBPT0mc3RhdGU9K21SUWUxZDZwQm9KcUY2QWIyOGtsZz09JnJlc3BvbnNlX3VyaT1odHRwczovL2luaml2ZXJpZnkuZGV2Mi5tb3NpcC5uZXQvcmVkaXJlY3QmY2xpZW50X21ldGFkYXRhPXsiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfYWxnIjoiRUNESC1FUyIsImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuYyI6IkEyNTZHQ00iLCJ2cF9mb3JtYXRzIjp7Im1zb19tZG9jIjp7ImFsZyI6WyJFUzI1NiIsIkVkRFNBIl19LCJsZHBfdnAiOnsicHJvb2ZfdHlwZSI6WyJFZDI1NTE5U2lnbmF0dXJlMjAxOCIsIkVkMjU1MTlTaWduYXR1cmUyMDIwIiwiUnNhU2lnbmF0dXJlMjAxOCJdfX19"

// jwt -> client_id_scheme = did
let testValidSignedVpRequestWithDid = "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6bW9zaXAuZ2l0aHViLmlvOmluamktbW9jay1zZXJ2aWNlczpvcGVuaWQ0dnAtc2VydmljZTpkb2NzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHBzOi8vN2FmOC0yNDAxLTQ5MDAtNzFjMi1mNzRhLThkODgtYWE1Yi0yZjE2LTI5NGIubmdyb2stZnJlZS5hcHAvdmVyaWZpZXIvZ2V0LWF1dGgtcmVxdWVzdC1vYmomcmVxdWVzdF91cmlfbWV0aG9kPWdldCBIVFRQLzEuMQ=="

let testInValidSignedVpRequestWithDidAndClientIdDifferent = "openid4vp://authorize?Y2xpZW50X2lkPWRpZDp3ZWI6bW9zaXAuZ2l0aHViLmlvOmluamktbW9jay1zZXJ2aWNlczpvcGVuaWQ0dnAtc2VydmljZTpkb2NzJmNsaWVudF9pZF9zY2hlbWU9ZGlkJnJlcXVlc3RfdXJpPWh0dHBzOi8vN2FmOC0yNDAxLTQ5MDAtNzFjMi1mNzRhLThkODgtYWE1Yi0yZjE2LTI5NGIubmdyb2stZnJlZS5hcHAvdmVyaWZpZXIvZ2V0LWF1dGgtcmVxdWVzdC1vYmomcmVxdWVzdF91cmlfbWV0aG9kPWdldCBIVFRQLzEuMQ=="

let testInvalidPresentationDefinitionVpRequest = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXByZS1yZWdpc3RlcmVkJnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaW5wdXRfZGVzY3JpcHRvcnMiOltdfSZyZXNwb25zZV90eXBlPXZwX3Rva2VuJnJlc3BvbnNlX21vZGU9ZGlyZWN0X3Bvc3Qmbm9uY2U9VmJSUkIvTFR4TGlYbVZOWnV5TU84QT09JnN0YXRlPSttUlFlMWQ2cEJvSnFGNkFiMjhrbGc9PSZyZXNwb25zZV91cmk9aHR0cHM6Ly9pbmppdmVyaWZ5LmRldjIubW9zaXAubmV0L3JlZGlyZWN0"

let invalidVpRequest = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZwcmVzZW50YXRpb25fZGVmaW5pdGlvbj17ImlucHV0X2Rlc2NyaXB0b3JzIjpbXX0mcmVzcG9uc2VfdHlwZT12cF90b2tlbiZyZXNwb25zZV9tb2RlPWRpcmVjdF9wb3N0Jm5vbmNlPVZiUlJCL0xUeExpWG1WTlp1eU1POEE9PSZzdGF0ZT0rbVJRZTFkNnBCb0pxRjZBYjI4a2xnPT0mcmVzcG9uc2VfdXJpPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldC9yZWRpcmVjdA=="

let invalidClientMetadata =
"OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXByZS1yZWdpc3RlcmVkJnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaWQiOiIjMjM0NTMzMyIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6ImJhbmtpbmdfaW5wdXRfMSIsImZvcm1hdCI6IHsibGRwX3ZjIjogeyJwcm9vZl90eXBlIjogWyJFZDI1NTE5U2lnbmF0dXJlMjAxOCJdfX0sIm5hbWUiOiJCYW5rIEFjY291bnQgSW5mb3JtYXRpb24iLCJwdXJwb3NlIjoiV2UgY2FuIG9ubHkgcmVtaXQgcGF5bWVudCB0byBhIGN1cnJlbnRseS12YWxpZCBiYW5rIGFjY291bnQgaW4gdGhlIFVTLCBGcmFuY2UsIG9yIEdlcm1hbnksIHN1Ym1pdHRlZCBhcyBhbiBBQkEgQWNjdCBvciBJQkFOLiIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLmNyZWRlIl0sInB1cnBvc2UiOiJXZSBjYW4gdXNlIGZvciAgIyB2ZXJpZmljYXRpb24gcHVycG9zZSAjIGZvciBhbnl0aGluZyIsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwicGF0dGVybiI6Il5bMC05XXs5fXxeKFthLXpBLVpdKXs0fShbYS16QS1aXSl7Mn0oWzAtOWEtekEtWl0pezJ9KFswLTlhLXpBLVpdezN9KT8kIn19LHsicGF0aCI6WyIkLnZjLmNyZWRlbnRpYWwiLCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmFjY291bnRbKl0ucm91dGUiLCIkLmFjY291bnRbKl0ucm91dGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yIHZlcmlmaWNhdGlvbiBwdXJwb3NlIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX1dfX1dfSZyZXNwb25zZV90eXBlPXZwX3Rva2VuJnJlc3BvbnNlX21vZGU9ZGlyZWN0X3Bvc3Qmbm9uY2U9VmJSUkIvTFR4TGlYbVZOWnV5TU84QT09JnN0YXRlPSttUlFlMWQ2cEJvSnFGNkFiMjhrbGc9PSZyZXNwb25zZV91cmk9aHR0cHM6Ly9pbmppdmVyaWZ5LmRldjIubW9zaXAubmV0L3JlZGlyZWN0JmNsaWVudF9tZXRhZGF0YT17fQ=="
let validJwtResponse = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6IntcImlkXCI6XCJ2cCB0b2tlbiBleGFtcGxlXCIsXCJwdXJwb3NlXCI6XCJSZWx5aW5nIHBhcnR5IGlzIHJlcXVlc3RpbmcgeW91ciBkaWdpdGFsIElEIGZvciB0aGUgcHVycG9zZSBvZiBTZWxmLUF1dGhlbnRpY2F0aW9uXCIsXCJmb3JtYXRcIjp7XCJsZHBfdmNcIjp7XCJwcm9vZl90eXBlXCI6W1wiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwiaW5wdXRfZGVzY3JpcHRvcnNcIjpbe1wiaWRcIjpcImlkIGNhcmQgY3JlZGVudGlhbFwiLFwiZm9ybWF0XCI6e1wibGRwX3ZjXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCJdfX0sXCJjb25zdHJhaW50c1wiOntcImZpZWxkc1wiOlt7XCJwYXRoXCI6W1wiJC5jcmVkZW50aWFsU3ViamVjdC5lbWFpbFwiXSxcImZpbHRlclwiOntcInR5cGVcIjpcInN0cmluZ1wiLFwicGF0dGVyblwiOlwiQGdtYWlsLmNvbVwifX1dfX1dfSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoiU2EycUdXZTY4VmJidGx2ZUxxbjFzZz09Iiwibm9uY2UiOiIvTEUzS0ZpaFhsM3hUNjhLeWJob3NBPT0iLCJjbGllbnRfaWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovLzQ2YjItNDUtMTEyLTY4LTE5MC5uZ3Jvay1mcmVlLmFwcC92ZXJpZmllci92cC1yZXNwb25zZSJ9.HIw6vs2S9OzZ2xX7y74J1cEsb420xm126h0AnbR97XGjCnjCeG1C5McxPPlwcLkVFHLmjdc-p4NeJTGLV-tRCg"

let invalidJwtResponse = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyNrZXktMCJ9.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6IntcImlkXCI6XCJ2cCB0b2tlbiBleGFtcGxlXCIsXCJwdXJwb3NlXCI6XCJSZWx5aW5nIHBhcnR5IGlzIHJlcXVlc3RpbmcgeW91ciBkaWdpdGFsIElEIGZvciB0aGUgcHVycG9zZSBvZiBTZWxmLUF1dGhlbnRpY2F0aW9uXCIsXCJmb3JtYXRcIjp7XCJsZHBfdmNcIjp7XCJwcm9vZl90eXBlXCI6W1wiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwiaW5wdXRfZGVzY3JpcHRvcnNcIjpbe1wiaWRcIjpcImlkIGNhcmQgY3JlZGVudGlhbFwiLFwiZm9ybWF0XCI6e1wibGRwX3ZjXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCJdfX0sXCJjb25zdHJhaW50c1wiOntcImZpZWxkc1wiOlt7XCJwYXRoXCI6W1wiJC5jcmVkZW50aWFsU3ViamVjdC5lbWFpbFwiXSxcImZpbHRlclwiOntcInR5cGVcIjpcInN0cmluZ1wiLFwicGF0dGVyblwiOlwiQGdtYWlsLmNvbVwifX1dfX1dfSIsImNsaWVudF9tZXRhZGF0YSI6IntcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiLFwiRWREU0FcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19LFwicmVxdWlyZV9zaWduZWRfcmVxdWVzdF9vYmplY3RcIjp0cnVlfSIsInN0YXRlIjoiU2EycUdXZTY4VmJidGx2ZUxxbjFzZz09Iiwibm9uY2UiOiIvTEUzS0ZpaFhsM3hUNjhLeWJob3NBPT0iLCJjbGllbnRfaWQiOiJkaWQ6d2ViOm1vc2lwLmdpdGh1Yi5pbzppbmppLW1vY2stc2VydmljZXM6b3BlbmlkNHZwLXNlcnZpY2U6ZG9jcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV91cmkiOiJodHRwczovLzQ2YjItNDUtMTEyLTY4LTE5MC5uZ3Jvay1mcmVlLmFwcC92ZXJpZmllci92cC1yZXNwb25zZSJ9.HIw6vs2S9OzZ2xX7y74J1cEsb420xm126h0AnbR97XGjCnjCeG1C5McxPPlwcLkVFHLmjdc-p4NeJTGLV-tRCg"

let invalidJwtResponseWithoutKid = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiIifQ.eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6IntcImlkXCI6XCJ2cCB0b2tlbiBleGFtcGxlXCIsXCJwdXJwb3NlXCI6XCJSZWx5aW5nIHBhcnR5IGlzIHlvdXIgZGlnaXRhbCBJRCBmb3IgdGhlIHB1cnBvc2Ugb2YgU2VsZi1BdXRoZW50aWNhdGlvblwiLFwiZm9ybWF0XCI6e1wibGRwX3ZjXCI6e1wicHJvb2ZfdHlwZVwiOltcIlJzYVNpZ25hdHVyZTIwMThcIl19fSxcImlucHV0X2Rlc2NyaXB0b3JzXCI6W3tcImlkXCI6XCJpZCBjYXJkIGNyZWRlbnRpYWxcIixcImZvcm1hdFwiOntcImxkcF92Y1wiOntcInByb29mX3R5cGVcIjpbXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiXX19LFwiY29uc3RyYWludHNcIjp7XCJmaWVsZHNcIjpbe1wicGF0aFwiOltcIiQuY3JlZGVudGlhbFN1YmplY3QuZW1haWxcIl0sXCJmaWx0ZXJcIjp7XCJ0eXBlXCI6XCJzdHJpbmdcIixcInBhdHRlcm5cIjpcIkBnbWFpbC5jb21cIn19XX19XX0iLCJjbGllbnRfbWV0YWRhdGEiOiJ7XCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9hbGdcIjpcIkVDREgtRVNcIixcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuY1wiOlwiQTI1NkdDTVwiLFwidnBfZm9ybWF0c1wiOntcIm1zb19tZG9jXCI6e1wiYWxnXCI6W1wiRVMyNTZcIixcIkVkRFNBXCJdfSxcImxkcF92cFwiOntcInByb29mX3R5cGVcIjpbXCJFZDI1NTE5U2lnbmF0dXJlMjAxOFwiLFwiRWQyNTUxOVNpZ25hdHVyZTIwMjBcIixcIlJzYVNpZ25hdHVyZTIwMThcIl19fSxcInJlcXVpcmVfc2lnbmVkX3JlcXVlc3Rfb2JqZWN0XCI6dHJ1ZX0iLCJzdGF0ZSI6IlNhMnFHV2U2OFZiYnRsdmVMcW4xc2c9PSIsIm5vbmNlIjoiL0xFM0tGaWhYbDN4VDY4S3liaG9zQT09IiwiY2xpZW50X2lkIjoiZGlkOndlYjptb3NpcC5naXRodWIuaW86aW5qaS1tb2NrLXNlcnZpY2VzOm9wZW5pZDR2cC1zZXJ2aWNlOmRvY3MiLCJjbGllbnRfaWRfc2NoZW1lIjoiZGlkIiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0IiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly80NmIyLTQ1LTExMi02OC0xOTAubmdyb2stZnJlZS5hcHAvdmVyaWZpZXIvdnAtcmVzcG9uc2UifQ.Se5BKaNrzZNePvRD03h1kHbY3uHgLyLuBvseciPe8y4O8f5oBxC0OIM5qzm_jT5uh6ZKEdEyRLl1FusPQVpHAA"

let paramsFromQRData = [
    "client_id": "did:web:adityankannan-tw.github.io:openid4vp:files",
    "client_id_scheme": "did",
    "request_uri": "https://7af8-2401-4900-71c2-f74a-8d88-aa5b-2f16-294b.ngrok-free.app/verifier/get-auth-request-obj",
    "request_uri_method": "get"
]

let resquestUriResponseData: [String: Any] = [
    "client_id": "https://injiverify.dev2.mosip.net",
    "client_id_scheme": "redirect_uri",
    "redirect_uri": "https://injiverify.dev2.mosip.net",
    "presentation_definition": [
        "id": "123",
        "input_descriptors": [
            [
                "id": "banking_input_1",
                "format": [
                    "ldp_vc": [
                        "proof_type": ["Ed25519Signature2018"]
                    ]
                ],
                "name": "Bank Account Information",
                "purpose": "hiiii",
                "constraints": [
                    "fields": [
                        [
                            "path": ["$.crede"],
                            "purpose": "We can use for # verification purpose # for anything",
                            "filter": [
                                "type": "string",
                                "pattern": "^[0-9]{9}|^([a-zA-Z]){4}([a-zA-Z]){2}([0-9a-zA-Z]){2}([0-9a-zA-Z]{3})?$"
                            ]
                        ],
                        [
                            "path": ["$.vc.credential", "$.vc.credentialSubject.account[*].route", "$.account[*].route"],
                            "purpose": "We can use for verification purpose",
                            "filter": [
                                "type": "string",
                                "pattern": "^[0-9]{9}|^([a-zA-Z]){4}([a-zA-Z]){2}([0-9a-zA-Z]){2}([0-9a-zA-Z]{3})?$"
                            ]
                        ]
                    ]
                ]
            ]
        ]
    ],
    "response_type": "vp_token",
    "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
    "state": "+mRQe1d6pBoJqF6Ab28klg==",
    "client_metadata": [
        "authorization_encrypted_response_alg": "ECDH-ES",
        "authorization_encrypted_response_enc": "A256GCM",
        "vp_formats": [
            "mso_mdoc": [
                "alg": ["ES256", "EdDSA"]
            ],
            "ldp_vp": [
                "proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]
            ]
        ]
    ]
]

