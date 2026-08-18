import Foundation

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

public struct BrowserApp: Identifiable, Equatable, Hashable {
    public let id: String
    public let displayName: String
    public let isDefault: Bool

    let probeURL: URL?
    let redirectURLBuilder: RedirectURLBuilder

    public static func == (lhs: BrowserApp, rhs: BrowserApp) -> Bool {
        return lhs.id == rhs.id
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    func redirectURL(for redirectUri: String) -> URL? {
        guard let url = sanitizeRedirectUri(redirectUri).flatMap({ URL(string: $0) }) else {
            return nil
        }
        return redirectURLBuilder.build(from: url)
    }
}

enum RedirectURLBuilder: Equatable {
    case systemDefault
    case replaceScheme(http: String, https: String)
    case percentEncodedQuery(prefix: String)
    case schemeless(prefix: String)

    func build(from url: URL) -> URL? {
        switch self {
        case .systemDefault:
            return url

        case let .replaceScheme(httpReplacement, httpsReplacement):
            guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let scheme = components.scheme?.lowercased()
            else { return nil }

            switch scheme {
            case "http": components.scheme = httpReplacement
            case "https": components.scheme = httpsReplacement
            default: return nil
            }
            return components.url

        case let .percentEncodedQuery(prefix):
            guard let encoded = url.absoluteString
                .addingPercentEncoding(withAllowedCharacters: .rfc3986Unreserved)
            else { return nil }
            return URL(string: prefix + encoded)

        case let .schemeless(prefix):
            guard let scheme = url.scheme else { return nil }
            let schemeless = String(url.absoluteString.dropFirst("\(scheme)://".count))
            guard !schemeless.isEmpty else { return nil }
            return URL(string: prefix + schemeless)
        }
    }
}

public extension BrowserApp {
    static let systemDefault = BrowserApp(
        id: "default",
        displayName: "Default browser",
        isDefault: true,
        probeURL: nil,
        redirectURLBuilder: .systemDefault
    )

    static let chrome = BrowserApp(
        id: "chrome",
        displayName: "Chrome",
        isDefault: false,
        probeURL: URL(string: "googlechromes://verifier.example.com"),
        redirectURLBuilder: .replaceScheme(http: "googlechrome", https: "googlechromes")
    )

    static let firefox = BrowserApp(
        id: "firefox",
        displayName: "Firefox",
        isDefault: false,
        probeURL: URL(string: "firefox://open-url?url=https%3A%2F%2Fverifier.example.com"),
        redirectURLBuilder: .percentEncodedQuery(prefix: "firefox://open-url?url=")
    )

    static let edge = BrowserApp(
        id: "edge",
        displayName: "Edge",
        isDefault: false,
        probeURL: URL(string: "microsoft-edge-https://verifier.example.com"),
        redirectURLBuilder: .replaceScheme(http: "microsoft-edge-http", https: "microsoft-edge-https")
    )

    static let brave = BrowserApp(
        id: "brave",
        displayName: "Brave",
        isDefault: false,
        probeURL: URL(string: "brave://open-url?url=https%3A%2F%2Fverifier.example.com"),
        redirectURLBuilder: .percentEncodedQuery(prefix: "brave://open-url?url=")
    )

    static let opera = BrowserApp(
        id: "opera",
        displayName: "Opera Touch",
        isDefault: false,
        probeURL: URL(string: "touch-https://verifier.example.com"),
        redirectURLBuilder: .replaceScheme(http: "touch-http", https: "touch-https")
    )

    static let duckDuckGo = BrowserApp(
        id: "duckduckgo",
        displayName: "DuckDuckGo",
        isDefault: false,
        probeURL: URL(string: "ddgQuickLink://verifier.example.com"),
        redirectURLBuilder: .schemeless(prefix: "ddgQuickLink://")
    )

    static let knownBrowsers: [BrowserApp] = [chrome, firefox, edge, brave, opera, duckDuckGo]
}

public protocol BrowserURLOpening {
    func canOpen(_ url: URL) async -> Bool

    @discardableResult
    func open(_ url: URL) async -> Bool
}

public final class BrowserURLOpener: BrowserURLOpening {

    public init() {}

    public func canOpen(_ url: URL) async -> Bool {
        #if canImport(UIKit)
        return await MainActor.run { UIApplication.shared.canOpenURL(url) }
        #elseif canImport(AppKit)
        return await MainActor.run { NSWorkspace.shared.urlForApplication(toOpen: url) != nil }
        #else
        return false
        #endif
    }

    @discardableResult
    public func open(_ url: URL) async -> Bool {
        #if canImport(UIKit)
        return await withCheckedContinuation { continuation in
            Task { @MainActor in
                UIApplication.shared.open(url, options: [:]) { opened in
                    continuation.resume(returning: opened)
                }
            }
        }
        #elseif canImport(AppKit)
        return await MainActor.run { NSWorkspace.shared.open(url) }
        #else
        return false
        #endif
    }
}

public final class BrowserRedirectHandler {

    private static let className = String(describing: BrowserRedirectHandler.self)

    private let urlOpener: BrowserURLOpening

    public init(urlOpener: BrowserURLOpening = BrowserURLOpener()) {
        self.urlOpener = urlOpener
    }

    public func getAvailableBrowsers() async -> [BrowserApp] {
        var availableBrowsers: [BrowserApp] = [.systemDefault]

        for browser in BrowserApp.knownBrowsers {
            guard let probeURL = browser.probeURL else { continue }
            if await urlOpener.canOpen(probeURL) {
                availableBrowsers.append(browser)
            }
        }

        return availableBrowsers
    }

    public func canRedirect(_ verifierResponse: VerifierResponse?) -> Bool {
        return isNavigableRedirectUri(verifierResponse?.redirectUri)
    }

    public func shouldOfferBrowserChoice(_ verifierResponse: VerifierResponse?) -> Bool {
        return isBrowserNavigableRedirectUri(verifierResponse?.redirectUri)
    }

    @discardableResult
    public func redirect(
        _ verifierResponse: VerifierResponse?,
        using browser: BrowserApp? = nil
    ) async -> Bool {
        return await redirect(redirectUri: verifierResponse?.redirectUri, using: browser)
    }

    @discardableResult
    public func redirect(
        redirectUri: String?,
        using browser: BrowserApp? = nil
    ) async -> Bool {
        guard let sanitizedRedirectUri = sanitizeRedirectUri(redirectUri) else {
            if let redirectUri,
               !redirectUri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                OpenID4VPException.warn(
                    "Verifier returned a redirect_uri that is not an absolute navigable URI. Redirection is skipped.",
                    className: Self.className
                )
            }
            return false
        }

        let selectedBrowser = isBrowserNavigableRedirectUri(sanitizedRedirectUri)
            ? (browser ?? .systemDefault)
            : .systemDefault

        guard let redirectURL = selectedBrowser.redirectURL(for: sanitizedRedirectUri) else {
            OpenID4VPException.warn(
                "Unable to build a \(selectedBrowser.displayName) URL for the redirect_uri returned by the Verifier.",
                className: Self.className
            )
            return false
        }

        let opened = await urlOpener.open(redirectURL)
        if !opened {
            OpenID4VPException.warn(
                "No application on the device was able to open the redirect_uri returned by the Verifier.",
                className: Self.className
            )
        }
        return opened
    }
}

private extension CharacterSet {
    static let rfc3986Unreserved = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
}
