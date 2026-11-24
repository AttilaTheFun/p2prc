import ConvoCore
import ConvoSession
import ConvoNet
import Foundation

/// §13.1 as decisions: which hosts to write to, whether a host-change
/// fork is due, what the replacement set is, and the rendezvous fallback.
public enum HostPolicy {
    public struct Bounds: Sendable {
        public var minHealthy = Parameters.Client.minHealthyHosts
        public var minTotal = Parameters.Client.minTotalHosts
        public var maxTotal = Parameters.Client.maxTotalHosts
        public var target: Int { min(minTotal + 1, maxTotal) }
        public init() {}
    }

    /// The hosts a sender publishes to: every healthy one in the set.
    public static func writeSet(_ hosts: [PublicKey], health: NodeHealth, at now: Date = Date()) -> [PublicKey] {
        health.healthy(hosts, at: now)
    }

    public static func hostChangeDue(_ hosts: [PublicKey], health: NodeHealth, bounds: Bounds = Bounds(), at now: Date = Date()) -> Bool {
        health.healthy(hosts, at: now).count < bounds.minHealthy
    }

    /// The child's `home_nodes`: the still-healthy hosts plus candidates
    /// from `RV(group_id, 16)` over the client's directory in rank order,
    /// skipping unhealthy ones, up to `target`.
    public static func replacementHosts(current: [PublicKey], groupID: Hash32, directory: [PublicKey], health: NodeHealth,
                                        bounds: Bounds = Bounds(), at now: Date = Date()) -> [PublicKey] {
        var set = health.healthy(current, at: now)
        for candidate in Rendezvous.select(key: groupID, from: directory, count: Parameters.Client.maxHomeNodes) where set.count < bounds.target {
            if !set.contains(candidate), health.isHealthy(candidate, at: now) { set.append(candidate) }
        }
        return set
    }

    /// `member_idx × FORK_STAGGER`.
    public static func forkDelay(memberIdx: UInt8) -> TimeInterval { Double(memberIdx) * Parameters.Client.forkStaggerSeconds }

    /// `RV(key, k_rv)` (§13.1): the top nodes of the client's directory
    /// that are healthy and not proven faulty, by `H("convo/rv" ‖ key ‖ node_pk)`.
    public static func rendezvous(key: Hash32, directory: [PublicKey], health: NodeHealth? = nil, at now: Date = Date()) -> [PublicKey] {
        let candidates = health.map { $0.healthy(directory, at: now) } ?? directory
        return Rendezvous.select(key: key, from: candidates, count: Parameters.Client.rendezvousSetSize)
    }
}
