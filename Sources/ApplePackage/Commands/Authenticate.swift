//
//  Authenticate.swift
//  ApplePackage
//
//  Created by QAQ on 2023/10/4.
//

import AsyncHTTPClient
import Foundation
import NIOHTTP1

public actor Authenticator {
    private enum LoginResponse {
        case success(Account)
        case codeRequired
        case redirect(URL)
        case retry
        case failure(String)
    }

    private let signer: SAPSigner
    private let deviceIdentifier: String
    private var endpoint: URL
    private var cookies: [Cookie]
    private var storeFront = ""
    private var pod: String?
    private var authenticating = false

    /// Extra headers attached to every sign-in request (e.g. Anisette/ADI
    /// device-verification headers fetched from the user's own Anisette
    /// server). Empty by default: with no headers set, requests are built
    /// exactly as before. The headers are attached before the SAP signature
    /// is computed, so they travel on the authenticate and 2FA requests.
    public var anisetteHeaders: [String: String] = [:]

    /// Sets the extra Anisette headers. Call this instead of assigning
    /// `anisetteHeaders` directly: actor-isolated mutable state cannot be
    /// mutated from a nonisolated context, even with `await` (Swift 6).
    public func setAnisetteHeaders(_ headers: [String: String]) {
        anisetteHeaders = headers
    }

    /// A fresh SAP exchange is mandatory. Reuse this instance when supplying a verification code.
    public init(cookies: [Cookie] = []) async throws {
        deviceIdentifier = Configuration.deviceIdentifier
        let bag = try await Bag.fetchBag(redirectConfiguration: .disallow)
        endpoint = try Self.createInitialRequestEndpoint(baseURL: bag.authEndpoint, deviceIdentifier: deviceIdentifier)
        signer = try await SAPSigner.connect()
        self.cookies = cookies
    }

    public static func authenticate(email: String, password: String, code: String = "", cookies: [Cookie] = [], anisetteHeaders: [String: String] = [:]) async throws -> Account {
        let session = try await Authenticator(cookies: cookies)
        await session.setAnisetteHeaders(anisetteHeaders)
        return try await session.authenticate(email: email, password: password, code: code)
    }

    public func authenticate(email: String, password: String, code: String = "") async throws -> Account {
        guard !authenticating else { try ensureFailed("An authentication request is already in progress.") }
        authenticating = true
        defer { authenticating = false }
        let client = Configuration.makeHTTPClient(redirectConfiguration: .disallow)
        defer { _ = client.shutdown() }
        var retried = false
        var redirects = 0
        for _ in 0 ..< 5 {
            let request = try await Self.makeRequest(
                endpoint: endpoint, email: email, password: password, code: code, cookies: cookies, deviceIdentifier: deviceIdentifier,
                sapSigner: signer, anisetteHeaders: anisetteHeaders,
            )
            let accumulator = ResponseAccumulator(request: request, maxBodySize: 2 * 1024 * 1024)
            let response = try await client.execute(request: request, delegate: accumulator).futureResult.get()
            let result = try parseResponse(response, email: email, password: password, code: code)
            switch result {
            case let .success(account): return account
            case let .redirect(url):
                guard redirects < 3 else { try ensureFailed("Authentication redirect limit exceeded.") }
                guard let resolved = URL(string: url.relativeString, relativeTo: endpoint)?.absoluteURL else {
                    try ensureFailed(Strings.failedToRetrieveRedirect)
                }
                endpoint = try Self.approvedEndpoint(resolved)
                redirects += 1
            case .codeRequired: throw AuthenticationError.verificationCodeRequired
            case .retry:
                guard !retried else { try ensureFailed(Strings.authFailedUnknown) }
                retried = true
            case let .failure(message): try ensureFailed("\(Strings.authFailed): \(message)")
            }
        }
        try ensureFailed("Authentication redirect limit exceeded.")
    }

    /// Re-authenticates with the saved cookies to rotate the password token.
    /// `anisetteHeaders` (empty by default) are the Anisette/ADI device-
    /// verification headers fetched from the user's own Anisette server:
    /// without them Apple may refuse the request before judging the account
    /// (empty 204 / destination-less redirect), the same gate as sign-in.
    /// NVD: added for the "Add to Purchased" flow, which rotates the token
    /// before every purchase — previously it always authenticated
    /// header-less, so a purchase could fail with "failed to retrieve
    /// redirect location" even though sign-in itself carried headers.
    public static func rotatePasswordToken(for account: inout Account, anisetteHeaders: [String: String] = [:]) async throws {
        account = try await authenticate(email: account.email, password: account.password, cookies: account.cookie, anisetteHeaders: anisetteHeaders)
    }

    static func approvedEndpoint(_ url: URL) throws -> URL {
        guard url.scheme?.lowercased() == "https", let host = url.host?.lowercased(), host == "apple.com" || host.hasSuffix(".apple.com"),
              url.user == nil, url.password == nil, url.port == nil || url.port == 443
        else { try ensureFailed("Authentication requires an Apple HTTPS endpoint.") }
        return url
    }

    private static func createInitialRequestEndpoint(baseURL: URL, deviceIdentifier: String) throws -> URL {
        guard var comps = URLComponents(url: baseURL, resolvingAgainstBaseURL: true) else {
            try ensureFailed("\(Strings.invalidAuthEndpoint): \(baseURL)")
        }
        var query = comps.queryItems ?? []
        query.removeAll { $0.name == "guid" }
        query.append(URLQueryItem(name: "guid", value: deviceIdentifier))
        comps.queryItems = query
        return try approvedEndpoint(comps.url.get())
    }

    static func makeRequest(
        endpoint: URL, email: String, password: String, code: String, cookies: [Cookie], deviceIdentifier: String,
        sapSigner: any SAPRequestSigning, anisetteHeaders: [String: String] = [:],
    ) async throws -> HTTPClient.Request {
        let parameters: [String: String] = [
            "appleId": email, "attempt": "\(code.isEmpty ? "4" : "2")", "guid": deviceIdentifier, "password": "\(password)\(code)",
            "rmp": "0", "why": "signIn",
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: parameters, format: .xml, options: 0)
        var headers: [(String, String)] = [("User-Agent", Configuration.userAgent), ("Content-Type", "application/x-apple-plist")]
        for item in cookies.buildCookieHeader(endpoint) {
            headers.append(item)
        }
        // Anisette/ADI device-verification headers (from the user's own
        // Anisette server) go on before the SAP signature is computed.
        // Empty by default, so existing callers see no change.
        for (name, value) in anisetteHeaders {
            headers.append((name, value))
        }
        _ = try approvedEndpoint(endpoint)
        let signature = try await sapSigner.sign(data)
        headers.append(("X-Apple-ActionSignature", signature.base64EncodedString()))
        APLogger.logRequest(method: "POST", url: endpoint.absoluteString, headers: headers)
        return try .init(url: endpoint.absoluteString, method: .POST, headers: .init(headers), body: .data(data))
    }

    private func parseResponse(_ response: HTTPClient.Response, email: String, password: String, code: String) throws -> LoginResponse {
        APLogger.logResponse(
            status: response.status.code, headers: response.headers.map { ($0.name, $0.value) }, bodySize: response.body?.readableBytes,
        )

        cookies.mergeCookies(response.cookies)

        let readStoreFrontValue = response.headers["x-set-apple-store-front"].filter { !$0.isEmpty }.compactMap {
            $0.components(separatedBy: "-").first
        }.filter { !$0.isEmpty }
        assert(readStoreFrontValue.count <= 1)
        if let first = readStoreFrontValue.first {
            storeFront = first
        }

        if let podValue = response.headers.first(name: "pod"), !podValue.isEmpty {
            pod = podValue
        }

        let redirectStatuses: [HTTPResponseStatus] = [.movedPermanently, .found, .seeOther, .temporaryRedirect, .permanentRedirect]
        if redirectStatuses.contains(response.status) {
            guard let location = response.headers.first(name: "location"), let url = URL(string: location) else {
                return .failure(Strings.failedToRetrieveRedirect)
            }
            return .redirect(url)
        }

        guard response.status == .ok else { return .failure("HTTP \(response.status.code)") }
        guard var body = response.body, body.readableBytes <= 2 * 1024 * 1024, let data = body.readData(length: body.readableBytes) else {
            return .failure("response body is empty (code: \(response.status.code))")
        }

        let listItem = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        let dic = try (listItem as? [String: Any]).get(Strings.responseNotDictionary)

        if let failureType = dic["failureType"] as? String, failureType.isEmpty, code.isEmpty,
           let customerMessage = dic["customerMessage"] as? String, customerMessage == "MZFinance.BadLogin.Configurator_message"
        {
            return .codeRequired
        }

        if let failureType = dic["failureType"] as? String, failureType == "-5000" {
            return .retry
        }

        if let failureType = dic["failureType"] as? String, failureType == "5005" {
            return .failure(Strings.invalid2FACode)
        }

        let failureMessage = (dic["dialog"] as? [String: Any])?["explanation"] as? String ?? (dic["customerMessage"] as? String)
        let accountInfoDic = try (dic["accountInfo"] as? [String: Any]).get(failureMessage ?? Strings.missingAccountInfo)
        let addressInfoDic = try (accountInfoDic["address"] as? [String: Any]).get(failureMessage ?? Strings.missingAddress)

        let account = try Account(
            email: email, password: password, appleId: accountInfoDic["appleId"] as? String, store: storeFront,
            firstName: addressInfoDic["firstName"] as? String, lastName: addressInfoDic["lastName"] as? String,
            passwordToken: dic["passwordToken"] as? String, directoryServicesIdentifier: dic["dsPersonId"] as? String, cookie: cookies,
            pod: pod,
        )
        return .success(account)
    }
}
