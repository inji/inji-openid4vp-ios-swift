import Foundation
import XCTest
@testable import OpenID4VP

final class BrowserRedirectHandlerTests: XCTestCase {

    private let redirectUri =
        "https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"

    private func verifierResponse(redirectUri: String?) -> VerifierResponse {
        return VerifierResponse(
            statusCode: 200,
            responseBody: "",
            redirectUri: redirectUri,
            additionalParams: nil,
            headers: [:]
        )
    }

    /// Available browsers

    func testOnlyDefaultBrowserIsAvailableWhenNoBrowserSchemeIsDeclared() async {
        let urlOpener = MockBrowserURLOpener()

        let browsers = await BrowserRedirectHandler(urlOpener: urlOpener).getAvailableBrowsers()

        XCTAssertEqual(browsers.map(\.id), ["default"])
        XCTAssertTrue(browsers[0].isDefault)
    }

    func testInstalledBrowsersAreListedAfterTheDefaultBrowser() async {
        let urlOpener = MockBrowserURLOpener(installedSchemes: ["googlechromes", "firefox"])

        let browsers = await BrowserRedirectHandler(urlOpener: urlOpener).getAvailableBrowsers()

        XCTAssertEqual(browsers.map(\.id), ["default", "chrome", "firefox"])
    }

    func testBrowsersThatAreNotInstalledAreNotListed() async {
        let urlOpener = MockBrowserURLOpener(installedSchemes: ["ddgQuickLink".lowercased()])

        let browsers = await BrowserRedirectHandler(urlOpener: urlOpener).getAvailableBrowsers()

        XCTAssertEqual(browsers.map(\.id), ["default", "duckduckgo"])
    }

    /// Redirection

    func testRedirectsToTheRedirectUriReturnedByTheVerifier() async {
        let urlOpener = MockBrowserURLOpener()

        let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
            .redirect(verifierResponse(redirectUri: redirectUri))

        XCTAssertTrue(redirected)
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), [redirectUri])
    }

    func testOpensTheRedirectUriInTheBrowserChosenByTheEndUser() async {
        let urlOpener = MockBrowserURLOpener(installedSchemes: ["googlechromes"])

        let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
            .redirect(verifierResponse(redirectUri: redirectUri), using: .chrome)

        XCTAssertTrue(redirected)
        XCTAssertEqual(
            urlOpener.openedURLs.map(\.absoluteString),
            ["googlechromes://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"]
        )
    }

    func testOpensTheRedirectUriAsAnEncodedQueryParameterForFirefox() async {
        let urlOpener = MockBrowserURLOpener(installedSchemes: ["firefox"])

        let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
            .redirect(verifierResponse(redirectUri: "https://client.example.org/cb?a=1"), using: .firefox)

        XCTAssertTrue(redirected)
        XCTAssertEqual(
            urlOpener.openedURLs.map(\.absoluteString),
            ["firefox://open-url?url=https%3A%2F%2Fclient.example.org%2Fcb%3Fa%3D1"]
        )
    }

    func testOpensTheRedirectUriWithoutItsSchemeForDuckDuckGo() async {
        let urlOpener = MockBrowserURLOpener(installedSchemes: ["ddgquicklink"])

        let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
            .redirect(verifierResponse(redirectUri: "https://client.example.org/cb"), using: .duckDuckGo)

        XCTAssertTrue(redirected)
        XCTAssertEqual(urlOpener.openedURLs.count, 1)
        XCTAssertEqual(
            urlOpener.openedURLs.first?.absoluteString.caseInsensitiveCompare("ddgQuickLink://client.example.org/cb"),
            .orderedSame
        )
    }

    /// Lowercases only the scheme, so everything after `://` stays case sensitive.
    private func normalizingScheme(_ url: String) -> String {
        guard let separator = url.range(of: "://") else { return url }
        return url[..<separator.lowerBound].lowercased() + url[separator.lowerBound...]
    }

    private func assertRedirectURLs(
        redirectUri: String,
        cases: [(browser: BrowserApp, probeScheme: String, expectedURL: String)]
    ) async {
        XCTAssertEqual(cases.count, BrowserApp.knownBrowsers.count)

        for testCase in cases {
            let urlOpener = MockBrowserURLOpener(installedSchemes: [testCase.probeScheme])

            let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
                .redirect(verifierResponse(redirectUri: redirectUri), using: testCase.browser)

            XCTAssertTrue(redirected, "expected redirection for \(testCase.browser.displayName)")
            XCTAssertEqual(urlOpener.openedURLs.count, 1, "expected one open for \(testCase.browser.displayName)")
            XCTAssertEqual(
                urlOpener.openedURLs.first.map { normalizingScheme($0.absoluteString) },
                normalizingScheme(testCase.expectedURL),
                "unexpected URL for \(testCase.browser.displayName)"
            )
        }
    }

    func testBuildsTheExpectedRedirectUrlForEveryKnownBrowser() async {
        let encodedRedirectUri = "https%3A%2F%2Fclient.example.org%2Fcb"

        await assertRedirectURLs(
            redirectUri: "https://client.example.org/cb",
            cases: [
                (.chrome, "googlechromes", "googlechromes://client.example.org/cb"),
                (.firefox, "firefox", "firefox://open-url?url=\(encodedRedirectUri)"),
                (.edge, "microsoft-edge-https", "microsoft-edge-https://client.example.org/cb"),
                (.brave, "brave", "brave://open-url?url=\(encodedRedirectUri)"),
                (.opera, "touch-https", "touch-https://client.example.org/cb"),
                (.duckDuckGo, "ddgquicklink", "ddgQuickLink://client.example.org/cb")
            ]
        )
    }

    func testBuildsTheExpectedRedirectUrlForEveryKnownBrowserOverHttp() async {
        let encodedRedirectUri = "http%3A%2F%2Fclient.example.org%2Fcb"

        await assertRedirectURLs(
            redirectUri: "http://client.example.org/cb",
            cases: [
                (.chrome, "googlechrome", "googlechrome://client.example.org/cb"),
                (.firefox, "firefox", "firefox://open-url?url=\(encodedRedirectUri)"),
                (.edge, "microsoft-edge-http", "microsoft-edge-http://client.example.org/cb"),
                (.brave, "brave", "brave://open-url?url=\(encodedRedirectUri)"),
                (.opera, "touch-http", "touch-http://client.example.org/cb"),
                (.duckDuckGo, "ddgquicklink", "ddgQuickLink://client.example.org/cb")
            ]
        )
    }

    func testPreservesTheCaseOfThePathAndQueryOfTheRedirectUri() async {
        let encodedRedirectUri = "https%3A%2F%2Fclient.example.org%2FCb%3FRef%3DAbC"

        await assertRedirectURLs(
            redirectUri: "https://client.example.org/Cb?Ref=AbC",
            cases: [
                (.chrome, "googlechromes", "googlechromes://client.example.org/Cb?Ref=AbC"),
                (.firefox, "firefox", "firefox://open-url?url=\(encodedRedirectUri)"),
                (.edge, "microsoft-edge-https", "microsoft-edge-https://client.example.org/Cb?Ref=AbC"),
                (.brave, "brave", "brave://open-url?url=\(encodedRedirectUri)"),
                (.opera, "touch-https", "touch-https://client.example.org/Cb?Ref=AbC"),
                (.duckDuckGo, "ddgquicklink", "ddgQuickLink://client.example.org/Cb?Ref=AbC")
            ]
        )
    }

    func testKeepsThePlainHttpSchemeWhenOpeningAnHttpRedirectUri() async {
        let urlOpener = MockBrowserURLOpener(installedSchemes: ["googlechrome"])

        let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
            .redirect(verifierResponse(redirectUri: "http://client.example.org/cb"), using: .chrome)

        XCTAssertTrue(redirected)
        XCTAssertEqual(
            urlOpener.openedURLs.map(\.absoluteString),
            ["googlechrome://client.example.org/cb"]
        )
    }

    func testDoesNotRedirectWhenTheVerifierResponseHasNoRedirectUri() async {
        let urlOpener = MockBrowserURLOpener()
        let handler = BrowserRedirectHandler(urlOpener: urlOpener)

        var redirected = await handler.redirect(verifierResponse(redirectUri: nil))
        XCTAssertFalse(redirected)

        redirected = await handler.redirect(verifierResponse(redirectUri: ""))
        XCTAssertFalse(redirected)

        XCTAssertTrue(urlOpener.openedURLs.isEmpty)
    }

    func testDoesNotRedirectWhenTheRedirectUriIsMalformedOrRelative() async {
        let urlOpener = MockBrowserURLOpener()
        let handler = BrowserRedirectHandler(urlOpener: urlOpener)

        for uri in ["/cb?response_code=123", "https://client.example.org/a b", "https:///cb"] {
            let redirected = await handler.redirect(verifierResponse(redirectUri: uri))
            XCTAssertFalse(redirected, "expected \(uri) to be skipped")
        }

        XCTAssertTrue(urlOpener.openedURLs.isEmpty)
    }

    func testReportsFailureWhenNoApplicationCouldOpenTheRedirectUri() async {
        let urlOpener = MockBrowserURLOpener(openSucceeds: false)

        let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
            .redirect(verifierResponse(redirectUri: redirectUri))

        XCTAssertFalse(redirected)
        XCTAssertEqual(urlOpener.openedURLs.count, 1)
    }

    func testLetsTheSystemResolveAHandlerForANonHttpRedirectUri() async {
        let urlOpener = MockBrowserURLOpener(installedSchemes: ["googlechromes"])
        let appLink = "mywallet://verifier-callback?response_code=123"

        let redirected = await BrowserRedirectHandler(urlOpener: urlOpener)
            .redirect(verifierResponse(redirectUri: appLink), using: .chrome)

        XCTAssertTrue(redirected)
        XCTAssertEqual(urlOpener.openedURLs.map(\.absoluteString), [appLink])
    }

    /// Redirection capability checks

    func testReportsWhetherTheVerifierResponseCanBeRedirectedTo() {
        let handler = BrowserRedirectHandler(urlOpener: MockBrowserURLOpener())

        XCTAssertTrue(handler.canRedirect(verifierResponse(redirectUri: redirectUri)))
        XCTAssertTrue(handler.canRedirect(verifierResponse(redirectUri: "mywallet://callback")))
        XCTAssertFalse(handler.canRedirect(verifierResponse(redirectUri: nil)))
        XCTAssertFalse(handler.canRedirect(verifierResponse(redirectUri: "/relative")))
    }

    func testOffersABrowserChoiceOnlyForHttpRedirectUris() {
        let handler = BrowserRedirectHandler(urlOpener: MockBrowserURLOpener())

        XCTAssertTrue(handler.shouldOfferBrowserChoice(verifierResponse(redirectUri: redirectUri)))
        XCTAssertFalse(
            handler.shouldOfferBrowserChoice(verifierResponse(redirectUri: "mywallet://callback"))
        )
        XCTAssertFalse(handler.shouldOfferBrowserChoice(verifierResponse(redirectUri: nil)))
    }
}
