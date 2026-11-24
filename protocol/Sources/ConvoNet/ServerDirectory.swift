#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import ConvoFoundation
#endif

// The signaling-server directory (docs/architecture.md): what a node — a
// signaling server or a client — knows about signaling servers, how it
// health-checks them with backoff, when it evicts them, and how it walks the
// graph to find more. Pure state: the HTTP calls are the caller's, so the
// same logic runs in the Linux node (URLSession) and in the client (through
// the host bridge), and is tested with a fake clock.

/// A signaling server as this node last saw it.
public struct KnownServer: Codable, Equatable, Sendable {
    /// Base URL, normalized: scheme + host[:port][/path], no trailing slash.
    public var url: String
    /// The server's self-reported id (from `/healthcheck`), once seen.
    public var id: String?
    /// The static web host the server vouches for (its configured site).
    public var site: String?
    /// Whether it mints TURN credentials at `/ice`.
    public var turn: Bool
    /// Last passing health check, seconds since 1970; nil = never.
    public var lastHealthy: Double?
    /// Consecutive failed checks since the last pass.
    public var failures: Int
    /// When the next check is due.
    public var nextCheck: Double
    /// When this node first learned of it.
    public var addedAt: Double

    public init(url: String, now: Double) {
        self.url = url
        self.id = nil
        self.site = nil
        self.turn = false
        self.lastHealthy = nil
        self.failures = 0
        self.nextCheck = now
        self.addedAt = now
    }

    /// Passed its most recent check.
    public var isHealthy: Bool { lastHealthy != nil && failures == 0 }
}

/// What `/healthcheck` answers.
public struct HealthReport: Codable, Equatable, Sendable {
    public var ok: Bool
    public var id: String
    public var kind: String
    public var version: String
    public var site: String?
    public var turn: Bool
    public var now: Double

    public init(ok: Bool, id: String, kind: String = "signaling", version: String, site: String?, turn: Bool, now: Double) {
        self.ok = ok
        self.id = id
        self.kind = kind
        self.version = version
        self.site = site
        self.turn = turn
        self.now = now
    }
}

/// What `GET /servers` answers: the healthy servers a node knows, itself
/// first.
public struct ServerList: Codable, Equatable, Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var url: String
        public var id: String?
        public var site: String?
        public var turn: Bool
        public init(url: String, id: String?, site: String?, turn: Bool) {
            self.url = url
            self.id = id
            self.site = site
            self.turn = turn
        }
    }
    public var servers: [Entry]
    public init(servers: [Entry]) { self.servers = servers }
}

/// What `POST /servers` carries: URLs the sender believes are signaling
/// servers. The receiver takes none of them on faith — each is queued for
/// its own health check and only shared once it passes.
public struct Advertisement: Codable, Equatable, Sendable {
    public var knownSignalingServers: [String]
    enum CodingKeys: String, CodingKey { case knownSignalingServers = "known_signaling_servers" }
    public init(knownSignalingServers: [String]) { self.knownSignalingServers = knownSignalingServers }
}

public struct ServerDirectory: Codable, Equatable, Sendable {
    /// Health-check intervals after 1, 2, 3… consecutive failures; the last
    /// repeats. A pass returns to the first. The first steps are short: a
    /// client that launched without a network must not wait minutes once
    /// it has one, and a node that hiccupped once is back within a minute.
    public static let backoff: [Double] = [20, 60, 180, 600, 1800, 3600, 10_800, 86_400, 604_800]
    /// Interval between checks of a healthy server.
    public static let healthyInterval: Double = 600
    /// Failing for this long (since the last pass, or since first seen)
    /// evicts the record until someone advertises it again.
    public static let evictAfter: Double = 604_800
    /// Discovery walks are rate-limited to one per this interval.
    public static let discoveryInterval: Double = 3600

    public private(set) var servers: [String: KnownServer] = [:]
    /// How many healthy servers this node wants before it stops looking:
    /// 20 for a signaling server, 10 for a client.
    public var limit: Int
    /// When the last discovery walk started (0 = never).
    public var lastDiscovery: Double = 0

    public init(limit: Int) { self.limit = limit }

    /// "https://api.p2prc.org/" → "https://api.p2prc.org"; rejects anything
    /// that is not an http(s) URL with a host.
    public static func normalize(_ raw: String) -> String? {
        // By hand: FoundationEssentials (the wasm / Linux Foundation) has no
        // trimmingCharacters.
        var text = String(raw.drop(while: { $0.isWhitespace || $0.isNewline }))
        while let last = text.last, last.isWhitespace || last.isNewline { text.removeLast() }
        guard text.hasPrefix("http://") || text.hasPrefix("https://") else { return nil }
        while text.hasSuffix("/") { text.removeLast() }
        let afterScheme = text.dropFirst(text.hasPrefix("https://") ? 8 : 7)
        guard let host = afterScheme.split(separator: "/", maxSplits: 1).first, !host.isEmpty,
              !host.contains(" "), text.count <= 512 else { return nil }
        return text
    }

    /// Learn of a server. Returns true when it was new (and is now due for
    /// a check right away).
    @discardableResult
    public mutating func add(_ raw: String, now: Double) -> Bool {
        guard let url = Self.normalize(raw), servers[url] == nil else { return false }
        servers[url] = KnownServer(url: url, now: now)
        return true
    }

    public mutating func remove(_ url: String) { servers[url] = nil }

    /// A check passed.
    public mutating func recordHealthy(_ url: String, report: HealthReport?, now: Double) {
        guard var server = servers[url] else { return }
        server.lastHealthy = now
        server.failures = 0
        server.nextCheck = now + Self.healthyInterval
        if let report {
            server.id = report.id
            server.site = report.site
            server.turn = report.turn
        }
        servers[url] = server
    }

    /// A check failed. Returns true when the server has now been evicted.
    @discardableResult
    public mutating func recordFailure(_ url: String, now: Double) -> Bool {
        guard var server = servers[url] else { return false }
        server.failures += 1
        let since = server.lastHealthy ?? server.addedAt
        if now - since >= Self.evictAfter {
            servers[url] = nil
            return true
        }
        let step = min(server.failures, Self.backoff.count) - 1
        server.nextCheck = now + Self.backoff[step]
        servers[url] = server
        return false
    }

    /// Servers whose check is due, soonest first.
    public func due(now: Double) -> [KnownServer] {
        servers.values.filter { $0.nextCheck <= now }.sorted { $0.nextCheck < $1.nextCheck }
    }

    /// Healthy servers, most recently confirmed first.
    public var healthy: [KnownServer] {
        servers.values.filter(\.isHealthy).sorted { ($0.lastHealthy ?? 0) > ($1.lastHealthy ?? 0) }
    }

    /// Whether a discovery walk should start: short of the limit, and not
    /// walked within the last hour.
    public func shouldDiscover(now: Double) -> Bool {
        healthy.count < limit && now - lastDiscovery >= Self.discoveryInterval
    }

    public mutating func markDiscovery(now: Double) { lastDiscovery = now }

    /// The walk stops once this many are healthy.
    public var satisfied: Bool { healthy.count >= limit }

    public func encoded() -> String {
        guard let data = try? JSONEncoder().encode(self) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    public static func decode(_ text: String, limit: Int) -> ServerDirectory {
        guard let data = text.data(using: .utf8),
              var directory = try? JSONDecoder().decode(ServerDirectory.self, from: data) else {
            return ServerDirectory(limit: limit)
        }
        directory.limit = limit
        return directory
    }
}

/// One breadth-first walk over `GET /servers`, bounded by the directory's
/// limit. The caller fetches; this decides what to fetch next and absorbs
/// what came back.
public struct DiscoveryWalk: Equatable, Sendable {
    private var queue: [String]
    private var visited: Set<String> = []
    /// Every URL learned during the walk, in order.
    public private(set) var learned: [String] = []

    /// Start from the servers already known (healthy first) and the seeds.
    public init(from directory: ServerDirectory, seeds: [String]) {
        var start = directory.healthy.map(\.url)
        for seed in seeds.compactMap(ServerDirectory.normalize) where !start.contains(seed) {
            start.append(seed)
        }
        for server in directory.servers.values where !start.contains(server.url) {
            start.append(server.url)
        }
        queue = start
    }

    /// The next server to ask, or nil when the frontier is exhausted.
    public mutating func next() -> String? {
        while let url = queue.first {
            queue.removeFirst()
            if visited.insert(url).inserted { return url }
        }
        return nil
    }

    /// What `url` answered. Unknown servers join the frontier and are
    /// reported through `learned` so the caller can add them to its
    /// directory (where they queue for their own health check).
    public mutating func absorb(_ list: ServerList, from url: String) {
        for entry in list.servers {
            guard let normalized = ServerDirectory.normalize(entry.url),
                  !visited.contains(normalized), !queue.contains(normalized) else { continue }
            queue.append(normalized)
            if !learned.contains(normalized) { learned.append(normalized) }
        }
    }
}
