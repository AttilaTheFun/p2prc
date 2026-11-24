import ConvoCore
import ConvoFoundation
#if canImport(WASILibc)
import WASILibc
#endif

/// §13.1 host health, per client and local. A host is unhealthy while any
/// of: it has failed (no receipt, or
/// an unsigned/invalid response) continuously for `HOST_UNHEALTHY_AFTER`;
/// it failed a receipted-item fetch after `deadline` twice in a row;
/// or a fraud proof against it verified (permanent). Health recovers on
/// the next correct response. A decaying score (Appendix B.2, half-life
/// 24 h) ranks healthy hosts when the client needs `R` of them.
public struct NodeHealth: Sendable {
    public struct Entry: Sendable {
        public var score: Double = 0
        public var updated: Date
        public var fraudulent = false
        public var failingSince: Date?
        public var lateFetchFailures = 0
    }

    public private(set) var entries: [PublicKey: Entry] = [:]
    public var halfLife: TimeInterval = Parameters.Client.healthHalfLifeSeconds
    public var unhealthyAfter: TimeInterval = Parameters.Client.hostUnhealthyAfterSeconds

    public init() {}

    private func decayed(_ e: Entry, at now: Date) -> Double {
        let elapsed = max(0, now.timeIntervalSince(e.updated))
        return e.score * pow(0.5, elapsed / halfLife)
    }

    private func entry(_ node: PublicKey, at now: Date) -> Entry { entries[node] ?? Entry(updated: now) }

    /// A receipt or a valid signed response (success), or none (failure).
    public mutating func record(_ node: PublicKey, success: Bool, at now: Date = Date()) {
        var e = entry(node, at: now)
        guard !e.fraudulent else { return }
        e.score = decayed(e, at: now) + (success ? 1 : -2)
        e.updated = now
        if success { e.failingSince = nil } else if e.failingSince == nil { e.failingSince = now }
        entries[node] = e
    }

    /// A fetch of a receipted item attempted after its `deadline`.
    public mutating func recordLateFetch(_ node: PublicKey, success: Bool, at now: Date = Date()) {
        var e = entry(node, at: now)
        e.lateFetchFailures = success ? 0 : e.lateFetchFailures + 1
        entries[node] = e
        record(node, success: success, at: now)
    }

    public mutating func markFraudulent(_ node: PublicKey) {
        var e = entry(node, at: Date())
        e.fraudulent = true
        e.score = -.infinity
        entries[node] = e
    }

    public func isHealthy(_ node: PublicKey, at now: Date = Date()) -> Bool {
        guard let e = entries[node] else { return true }
        if e.fraudulent || e.lateFetchFailures >= 2 { return false }
        if let since = e.failingSince, now.timeIntervalSince(since) >= unhealthyAfter { return false }
        return true
    }

    public func score(_ node: PublicKey, at now: Date = Date()) -> Double {
        entries[node].map { $0.fraudulent ? -.infinity : decayed($0, at: now) } ?? 0
    }

    public func healthy(_ candidates: [PublicKey], at now: Date = Date()) -> [PublicKey] {
        candidates.filter { isHealthy($0, at: now) }
    }

    /// The best `count` healthy candidates by score, unknown nodes neutral.
    public func pick(_ count: Int, from candidates: [PublicKey], at now: Date = Date()) -> [PublicKey] {
        Array(healthy(candidates, at: now).sorted { score($0, at: now) > score($1, at: now) }.prefix(count))
    }
}
