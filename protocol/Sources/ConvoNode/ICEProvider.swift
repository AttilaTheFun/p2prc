import ConvoNet
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// What a signaling server hands clients at `/ice`: STUN/TURN entries in the
/// RFC shape (`{urls, username, credential}`), minted from whatever TURN the
/// operator configured through the environment. Three ways to configure it,
/// none of which leaves this process:
///
///   - `CONVO_TURN_URLS` + `CONVO_TURN_USERNAME` + `CONVO_TURN_CREDENTIAL`:
///     long-term credentials (any provider; coturn `lt-cred-mech`).
///   - `CONVO_TURN_URLS` + `CONVO_TURN_SECRET`: a TURN-REST shared secret
///     (coturn `use-auth-secret`, or this repo's relay); credentials are
///     HMAC-minted per client with a short TTL.
///   - `CLOUDFLARE_TURN_KEY_ID` + `CLOUDFLARE_TURN_API_TOKEN`: Cloudflare
///     Realtime's credential API, minted ahead on a refresh loop and served
///     from memory (one mint covers every client; the credential is a bearer
///     token with a TTL, like the others).
///
/// `CONVO_STUN_URLS` adds plain STUN entries in any mode.
public final class ICEProvider: @unchecked Sendable, ICESource {
    public enum Mode: Sendable {
        case none
        case staticCredentials(urls: [String], username: String, credential: String)
        case sharedSecret(urls: [String], credentials: TURNCredentials, ttl: Int)
        case cloudflare(keyID: String, apiToken: String)
    }

    public let mode: Mode
    public let stunURLs: [String]
    public var log: (@Sendable (String) -> Void)?

    private let lock = NSLock()
    private var cloudflareOffer: ICEServer?
    private var cloudflareExpires: Double = 0
    private var timer: DispatchSourceTimer?
    private static let cloudflareTTL = 3 * 3600
    /// Env override for tests / mocks (`CONVO_CF_API_BASE`).
    static var cloudflareAPIBase: String {
        ProcessInfo.processInfo.environment["CONVO_CF_API_BASE"] ?? "https://rtc.live.cloudflare.com/v1"
    }

    public init(mode: Mode, stunURLs: [String] = []) {
        self.mode = mode
        self.stunURLs = stunURLs
    }

    /// Whether `/ice` will carry TURN (a relay), not just STUN.
    public var offersTURN: Bool {
        if case .none = mode { return false }
        return true
    }

    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> ICEProvider {
        func list(_ key: String) -> [String] {
            (env[key] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        let stun = list("CONVO_STUN_URLS")
        let turnURLs = list("CONVO_TURN_URLS")
        if let keyID = env["CLOUDFLARE_TURN_KEY_ID"], let token = env["CLOUDFLARE_TURN_API_TOKEN"],
           !keyID.isEmpty, !token.isEmpty {
            return ICEProvider(mode: .cloudflare(keyID: keyID, apiToken: token), stunURLs: stun)
        }
        if !turnURLs.isEmpty, let secret = env["CONVO_TURN_SECRET"], !secret.isEmpty {
            return ICEProvider(
                mode: .sharedSecret(urls: turnURLs, credentials: TURNCredentials(secret: Array(secret.utf8)), ttl: 3600),
                stunURLs: stun
            )
        }
        if !turnURLs.isEmpty, let user = env["CONVO_TURN_USERNAME"], let cred = env["CONVO_TURN_CREDENTIAL"],
           !user.isEmpty, !cred.isEmpty {
            return ICEProvider(mode: .staticCredentials(urls: turnURLs, username: user, credential: cred), stunURLs: stun)
        }
        return ICEProvider(mode: .none, stunURLs: stun)
    }

    /// Starts the Cloudflare refresh loop (no-op in the other modes).
    public func start() {
        guard case .cloudflare = mode else { return }
        refreshCloudflare()
        let timer = DispatchSource.makeTimerSource(queue: .global())
        // Re-mint at a third of the TTL so a failed mint has two more tries
        // before the served credential expires.
        timer.schedule(deadline: .now() + .seconds(Self.cloudflareTTL / 3), repeating: .seconds(Self.cloudflareTTL / 3))
        timer.setEventHandler { [weak self] in self?.refreshCloudflare() }
        timer.resume()
        self.timer = timer
    }

    public func stop() { timer?.cancel() }

    /// The ICE list for one client, with the TTL of any credential in it.
    public func iceServers(for clientID: String, now: Date = Date()) -> (servers: [ICEServer], ttl: Int) {
        var out: [ICEServer] = []
        var ttl = 0
        switch mode {
        case .none:
            break
        case .staticCredentials(let urls, let username, let credential):
            out.append(.init(urls: urls, username: username, credential: credential))
            ttl = 86_400
        case .sharedSecret(let urls, let credentials, let lifetime):
            let minted = credentials.mint(for: clientID, ttl: lifetime, now: now)
            out.append(.init(urls: urls, username: minted.username, credential: minted.credential))
            ttl = minted.ttl
        case .cloudflare:
            lock.lock()
            let offer = cloudflareOffer
            let expires = cloudflareExpires
            lock.unlock()
            if let offer, expires > now.timeIntervalSince1970 {
                out.append(offer)
                ttl = Int(expires - now.timeIntervalSince1970)
            }
        }
        if !stunURLs.isEmpty { out.append(.init(urls: stunURLs, username: nil, credential: nil)) }
        return (out, ttl)
    }

    /// Cloudflare: POST generate-ice-servers, keep the answer until it ages.
    /// Synchronous on the caller's thread (the maintenance loop or a test).
    public func refreshCloudflare() {
        guard case .cloudflare(let keyID, let token) = mode,
              let url = URL(string: "\(Self.cloudflareAPIBase)/turn/keys/\(keyID)/credentials/generate-ice-servers") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["ttl": Self.cloudflareTTL])
        let (status, data) = HTTPFetch.perform(request)
        guard (200..<300).contains(status), let data, let offer = Self.flatten(data) else {
            log?("cloudflare: mint failed (\(status))")
            return
        }
        lock.lock()
        cloudflareOffer = offer
        cloudflareExpires = Date().timeIntervalSince1970 + Double(Self.cloudflareTTL) - 60
        lock.unlock()
        log?("cloudflare: credentials refreshed")
    }

    /// `turn:host:3478`, `turns:host:5349`, `stun:host:3478` and the
    /// portless forms; not the 53/80/443 alternates.
    static func isStandardPort(_ url: String) -> Bool {
        let noQuery = url.split(separator: "?", maxSplits: 1).first.map(String.init) ?? url
        guard let colon = noQuery.lastIndex(of: ":"), colon != noQuery.firstIndex(of: ":") else { return true }
        let port = noQuery[noQuery.index(after: colon)...]
        return port == "3478" || port == "5349"
    }

    /// Cloudflare answers `{iceServers: [...]}` (or one entry); fold it into
    /// one credentialed entry, TURN URLs first.
    static func flatten(_ data: Data) -> ICEServer? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let entries: [[String: Any]]
        if let list = root["iceServers"] as? [[String: Any]] { entries = list }
        else if let one = root["iceServers"] as? [String: Any] { entries = [one] }
        else { return nil }
        var urls: [String] = []
        var username: String?
        var credential: String?
        for entry in entries {
            // Cloudflare lists every port it answers on (53, 80, 443 as
            // well as the standard 3478/5349). Handing the whole list to
            // the ICE agents broke connections outright in testing (a Mac
            // and a browser on one machine never reached a data channel);
            // the standard ports alone pair reliably, so only they are
            // passed on.
            let entryURLs = ((entry["urls"] as? [String]) ?? (entry["urls"] as? String).map { [$0] } ?? [])
                .filter { Self.isStandardPort($0) }
            if let u = entry["username"] as? String, let c = entry["credential"] as? String {
                username = u
                credential = c
                urls = entryURLs + urls
            } else {
                urls += entryURLs
            }
        }
        guard !urls.isEmpty else { return nil }
        return .init(urls: urls, username: username, credential: credential)
    }
}

/// A blocking HTTP call for the maintenance thread: health checks, the
/// discovery walk, self-advertisement, the Cloudflare mint. Never called
/// from a request handler.
public enum HTTPFetch {
    private final class Box: @unchecked Sendable {
        let lock = NSLock()
        var result: (Int, Data?) = (-1, nil)
    }

    public static func perform(_ request: URLRequest) -> (status: Int, data: Data?) {
        let done = DispatchSemaphore(value: 0)
        let box = Box()
        URLSession.shared.dataTask(with: request) { data, response, _ in
            box.lock.lock()
            box.result = ((response as? HTTPURLResponse)?.statusCode ?? -1, data)
            box.lock.unlock()
            done.signal()
        }.resume()
        _ = done.wait(timeout: .now() + request.timeoutInterval + 5)
        box.lock.lock(); defer { box.lock.unlock() }
        return box.result
    }

    public static func get(_ url: String, timeout: TimeInterval = 8) -> (status: Int, data: Data?) {
        guard let u = URL(string: url) else { return (-1, nil) }
        var request = URLRequest(url: u)
        request.timeoutInterval = timeout
        return perform(request)
    }

    public static func postJSON(_ url: String, body: Data, timeout: TimeInterval = 8) -> (status: Int, data: Data?) {
        guard let u = URL(string: url) else { return (-1, nil) }
        var request = URLRequest(url: u)
        request.httpMethod = "POST"
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        return perform(request)
    }
}
