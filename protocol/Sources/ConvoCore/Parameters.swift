import ConvoFoundation

/// Appendix B: defaults, all tunable. Times in milliseconds unless named in seconds.
public enum Parameters {
    /// B.1: genesis parameters by group size.
    public struct GenesisDefaults: Hashable, Sendable {
        public var quorum: UInt8
        public var maxParents: UInt8 = 8
        public var maxPayload: UInt32 = 65_536
        public var maxUncommittedRepublish: UInt8 = 10

        public static func forMembers(_ n: Int) -> GenesisDefaults {
            precondition(n >= 1 && n <= 64, "groups hold 1…64 members")
            switch n {
            case 1: return GenesisDefaults(quorum: 1)
            case 2: return GenesisDefaults(quorum: 2)
            case 3...8: return GenesisDefaults(quorum: UInt8(max(2, n - 1)))
            default: return GenesisDefaults(quorum: UInt8((n + 1) / 2 + 1))
            }
        }
    }

    /// B.2: client policy.
    public enum Client {
        public static let attestMessages = 20
        public static let attestIntervalMs: UInt64 = 5 * 60_000
        public static let commitGraceMs: UInt64 = 2 * 60_000
        public static let recoveryPatienceSeconds: TimeInterval = 14 * 86_400
        public static let receiptTimeoutSeconds: TimeInterval = 5
        public static let healthHalfLifeSeconds: TimeInterval = 86_400
        /// §13.1 client bounds (development values; public launch suggests 3 / 5 / 10).
        public static let minHealthyHosts = 2
        public static let minTotalHosts = 3
        public static let maxTotalHosts = 10
        public static var targetTotalHosts: Int { minTotalHosts + 1 }
        public static let hostUnhealthyAfterSeconds: TimeInterval = 600
        public static let forkStaggerSeconds: TimeInterval = 30
        public static let rendezvousSetSize = 2
        public static let blobRedundancy = 2
        public static let hpkeRotationSeconds: TimeInterval = 30 * 86_400
        public static let keyPackageLifetimeSeconds: TimeInterval = 60 * 86_400
        public static let mlsUpdateIntervalSeconds: TimeInterval = 7 * 86_400
        public static let mlsUpdateIntervalMessages = 500
        /// The hard bound on `home_nodes` (§2).
        public static let maxHomeNodes = 16
        /// §6, §11: independent cosignatures that publish a checkpoint.
        public static let witnessQuorum = 2
    }

    /// B.3: node parameters.
    public enum Node {
        public static let commitIntervalMs: UInt64 = 5 * 60_000
        public static let batchMax = 4_096
        public static let deliveryWindowMs: UInt64 = 2 * 60_000
        public static let minRetentionMs: UInt64 = 30 * 86_400_000
        public static let archiveSeconds: TimeInterval = 7 * 86_400
        public static let reuploadSeconds: TimeInterval = 7 * 86_400
        /// §11: how far a checkpoint's time may be from a witness's clock.
        public static let witnessSkewMs: UInt64 = 5 * 60_000
        /// §15, §19: how old or how far ahead a signed request may be.
        public static let requestMaxAgeMs: UInt64 = 60 * 60_000
        public static let requestMaxAheadMs: UInt64 = 6 * 60_000
        /// §19.1: the longest a wake registration may last.
        public static let wakeLifetimeMs: UInt64 = 30 * 86_400_000
        public static let rendezvousBoxLifetimeSeconds: TimeInterval = 600
    }

    /// Unix milliseconds now, from this machine's clock.
    public static func nowMs() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
}
