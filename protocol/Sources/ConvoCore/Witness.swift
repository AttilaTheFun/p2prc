import ConvoFoundation

/// One batch as the log records it: the leaf `H("convo/cbatch-leaf" ‖ root ‖ time ‖ count)`.
public struct LogEntry: Hashable, Sendable, BorshCodable {
    public var root: Hash32
    /// Unix ms when the node closed the batch.
    public var time: UInt64
    public var count: UInt64

    public init(root: Hash32, time: UInt64, count: UInt64) {
        self.root = root; self.time = time; self.count = count
    }

    public var leaf: Hash32 { MMR.leaf(root: root, time: time, count: count) }

    public func borshEncode(into w: inout BorshWriter) { w.fixed(root); w.u64(time); w.u64(count) }
    public init(borshFrom r: inout BorshReader) throws { root = try r.hash32(); time = try r.u64(); count = try r.u64() }
}

/// §6: a node's signed checkpoint of its log after batch `seq`.
public struct Checkpoint: Hashable, Sendable, BorshCodable {
    public var nodePk: PublicKey
    /// The newest batch; the log holds `seq + 1` batches.
    public var seq: UInt64
    public var root: Hash32
    public var count: UInt64
    /// Unix ms when the node closed the batch.
    public var time: UInt64
    public var mmrPeaks: [Hash32]
    public var signature: [UInt8]

    public init(nodePk: PublicKey, seq: UInt64, root: Hash32, count: UInt64, time: UInt64, mmrPeaks: [Hash32], signature: [UInt8]) {
        self.nodePk = nodePk; self.seq = seq; self.root = root; self.count = count; self.time = time
        self.mmrPeaks = mmrPeaks; self.signature = signature
    }

    /// Signs a checkpoint of `mmr`, whose last leaf is `entry`.
    public static func sign(log mmr: MMR, entry: LogEntry, with nodeKey: SigningKey) -> Checkpoint {
        var checkpoint = Checkpoint(nodePk: nodeKey.publicKey, seq: mmr.size - 1, root: entry.root, count: entry.count,
                                    time: entry.time, mmrPeaks: mmr.peaks, signature: [])
        checkpoint.signature = nodeKey.sign(checkpoint.preimage)
        return checkpoint
    }

    /// The log's size: `seq + 1` batches.
    public var size: UInt64 { seq + 1 }
    public var entry: LogEntry { LogEntry(root: root, time: time, count: count) }

    private func encodeFields(into w: inout BorshWriter) {
        w.fixed(nodePk); w.u64(seq); w.fixed(root); w.u64(count); w.u64(time)
        w.vec(mmrPeaks) { w, p in w.fixed(p) }
    }

    /// `H("convo/ckpt" ‖ borsh(fields))`: what the node signs and witnesses cosign over.
    public var preimage: Hash32 {
        var w = BorshWriter(); encodeFields(into: &w)
        return Hashing.hash(Domain.checkpoint, w.bytes)
    }

    public var isSigned: Bool { Signature.verify(signature, hash: preimage, publicKey: nodePk) }

    public func borshEncode(into w: inout BorshWriter) { encodeFields(into: &w); w.fixed(signature) }
    public init(borshFrom r: inout BorshReader) throws {
        nodePk = try r.hash32(); seq = try r.u64(); root = try r.hash32(); count = try r.u64(); time = try r.u64()
        mmrPeaks = try r.vec { try $0.hash32() }
        signature = try r.fixed(64)
    }
}

/// §6: a witness's cosignature of a checkpoint.
public struct Cosignature: Hashable, Sendable, BorshCodable {
    public var witnessPk: PublicKey
    /// The witness's clock when it cosigned (unix ms).
    public var time: UInt64
    public var signature: [UInt8]

    public init(witnessPk: PublicKey, time: UInt64, signature: [UInt8]) {
        self.witnessPk = witnessPk; self.time = time; self.signature = signature
    }

    /// `H("convo/cosign" ‖ checkpoint.preimage ‖ time)`.
    public static func preimage(checkpoint: Checkpoint, time: UInt64) -> Hash32 {
        var w = BorshWriter(); w.fixed(checkpoint.preimage); w.u64(time)
        return Hashing.hash(Domain.cosignature, w.bytes)
    }

    public static func sign(_ checkpoint: Checkpoint, time: UInt64, with witnessKey: SigningKey) -> Cosignature {
        Cosignature(witnessPk: witnessKey.publicKey, time: time, signature: witnessKey.sign(preimage(checkpoint: checkpoint, time: time)))
    }

    public func verifies(_ checkpoint: Checkpoint) -> Bool {
        Signature.verify(signature, hash: Self.preimage(checkpoint: checkpoint, time: time), publicKey: witnessPk)
    }

    public func borshEncode(into w: inout BorshWriter) { w.fixed(witnessPk); w.u64(time); w.fixed(signature) }
    public init(borshFrom r: inout BorshReader) throws {
        witnessPk = try r.hash32(); time = try r.u64(); signature = try r.fixed(64)
    }
}

/// §6: a checkpoint with the cosignatures gathered for it.
public struct WitnessedCheckpoint: Hashable, Sendable, BorshCodable {
    public var checkpoint: Checkpoint
    public var cosignatures: [Cosignature]

    public init(checkpoint: Checkpoint, cosignatures: [Cosignature] = []) {
        self.checkpoint = checkpoint; self.cosignatures = cosignatures
    }

    /// The distinct witnesses, other than the node, whose cosignatures verify.
    public var witnesses: Set<PublicKey> {
        Set(cosignatures.filter { $0.witnessPk != checkpoint.nodePk && $0.verifies(checkpoint) }.map(\.witnessPk))
    }

    /// Signed by the node and cosigned by at least `quorum` distinct
    /// witnesses other than the node: the batches it covers are published.
    public func isPublished(quorum: Int = Parameters.Client.witnessQuorum) -> Bool {
        checkpoint.isSigned && witnesses.count >= quorum
    }

    /// Adds a cosignature, keeping one per witness.
    public mutating func add(_ cosignature: Cosignature) {
        guard cosignature.verifies(checkpoint), !cosignatures.contains(where: { $0.witnessPk == cosignature.witnessPk }) else { return }
        cosignatures.append(cosignature)
    }

    /// The witnesses' median cosigning time: when the network saw it.
    public var witnessedTime: UInt64? {
        let times = cosignatures.filter { $0.verifies(checkpoint) }.map(\.time).sorted()
        return times.isEmpty ? nil : times[times.count / 2]
    }

    public func borshEncode(into w: inout BorshWriter) {
        checkpoint.borshEncode(into: &w)
        w.vec(cosignatures) { w, c in c.borshEncode(into: &w) }
    }
    public init(borshFrom r: inout BorshReader) throws {
        checkpoint = try Checkpoint(borshFrom: &r)
        cosignatures = try r.vec { try Cosignature(borshFrom: &$0) }
    }

    public var wire: [UInt8] { borsh }
    public static func fromWire(_ bytes: [UInt8]) throws -> WitnessedCheckpoint {
        var r = BorshReader(bytes)
        let value = try WitnessedCheckpoint(borshFrom: &r)
        try r.finish()
        return value
    }
}

/// §11: what a node sends a witness: its new checkpoint and the log entries
/// the witness hasn't seen, from `fromSeq` on.
public struct WitnessRequest: Hashable, Sendable, BorshCodable {
    public var checkpoint: Checkpoint
    public var fromSeq: UInt64
    public var entries: [LogEntry]

    public init(checkpoint: Checkpoint, fromSeq: UInt64, entries: [LogEntry]) {
        self.checkpoint = checkpoint; self.fromSeq = fromSeq; self.entries = entries
    }

    public func borshEncode(into w: inout BorshWriter) {
        checkpoint.borshEncode(into: &w); w.u64(fromSeq)
        w.vec(entries) { w, e in e.borshEncode(into: &w) }
    }
    public init(borshFrom r: inout BorshReader) throws {
        checkpoint = try Checkpoint(borshFrom: &r); fromSeq = try r.u64()
        entries = try r.vec { try LogEntry(borshFrom: &$0) }
    }

    public var wire: [UInt8] { borsh }
    public static func fromWire(_ bytes: [UInt8]) throws -> WitnessRequest {
        var r = BorshReader(bytes)
        let value = try WitnessRequest(borshFrom: &r)
        try r.finish()
        return value
    }
}

/// §11: what a witness keeps of one node's log (its entries, about 48 bytes
/// a batch, and the newest checkpoint it cosigned) and the checks it makes
/// before cosigning the next.
public struct LogWitness: Hashable, Sendable {
    public enum Answer: Equatable, Sendable {
        case cosign(Cosignature)
        /// The request starts somewhere other than what the witness holds:
        /// resend from `size`.
        case resendFrom(size: UInt64)
        /// The checkpoint contradicts what the witness holds; `earlier` is the
        /// conflicting checkpoint it had, which with this one may be F6.
        case conflict(earlier: Checkpoint?)
        case rejected(String)
    }

    public let nodePk: PublicKey
    public private(set) var entries: [LogEntry] = []
    public private(set) var latest: WitnessedCheckpoint?

    public init(nodePk: PublicKey) { self.nodePk = nodePk }

    /// A witness's copy restored from storage.
    public init(nodePk: PublicKey, entries: [LogEntry], latest: WitnessedCheckpoint?) {
        self.nodePk = nodePk; self.entries = entries; self.latest = latest
    }

    public var size: UInt64 { UInt64(entries.count) }

    /// Checks a request against this log and, when it extends it honestly,
    /// cosigns with `witnessKey` at `now` (unix ms).
    public mutating func witness(_ request: WitnessRequest, now: UInt64, skew: UInt64 = Parameters.Node.witnessSkewMs,
                                 with witnessKey: SigningKey) -> Answer {
        let checkpoint = request.checkpoint
        guard checkpoint.nodePk == nodePk else { return .rejected("checkpoint is for another log") }
        guard checkpoint.isSigned else { return .rejected("bad checkpoint signature") }
        if let previous = latest?.checkpoint {
            if checkpoint.seq == previous.seq {
                return checkpoint == previous ? .cosign(Cosignature.sign(checkpoint, time: now, with: witnessKey)) : .conflict(earlier: previous)
            }
            guard checkpoint.seq > previous.seq else { return .conflict(earlier: previous) }
            guard checkpoint.time >= previous.time else { return .rejected("checkpoint time went backwards") }
        }
        guard request.fromSeq == size else { return .resendFrom(size: size) }
        guard checkpoint.time + skew >= now, checkpoint.time <= now + skew else { return .rejected("checkpoint time outside the witness's clock skew") }
        let extended = entries + request.entries
        guard UInt64(extended.count) == checkpoint.size, extended.last == checkpoint.entry else {
            return .rejected("entries don't reach the checkpoint")
        }
        guard MMR(leaves: extended.map(\.leaf)).peaks == checkpoint.mmrPeaks else { return .conflict(earlier: latest?.checkpoint) }
        entries = extended
        let cosignature = Cosignature.sign(checkpoint, time: now, with: witnessKey)
        var witnessed = WitnessedCheckpoint(checkpoint: checkpoint)
        witnessed.add(cosignature)
        latest = witnessed
        return .cosign(cosignature)
    }

    /// Records a newer witnessed checkpoint seen elsewhere (gossip), keeping
    /// the one with the most cosignatures for the newest `seq`.
    public mutating func observe(_ witnessed: WitnessedCheckpoint) {
        guard witnessed.checkpoint.nodePk == nodePk, witnessed.checkpoint.isSigned else { return }
        if let current = latest, current.checkpoint.seq == witnessed.checkpoint.seq, current.checkpoint == witnessed.checkpoint {
            var merged = current
            for cosignature in witnessed.cosignatures { merged.add(cosignature) }
            latest = merged
        } else if latest == nil || witnessed.checkpoint.seq > latest!.checkpoint.seq {
            latest = witnessed
        }
    }
}

extension Checkpoint {
    /// F6 (§17): two checkpoints this node signed that can't both be its
    /// history: the same `seq` with different contents, or a later one whose
    /// log, given the entries between them, doesn't extend the earlier's.
    /// `entries` are the log's entries from the start through `later`.
    public static func equivocate(_ a: Checkpoint, _ b: Checkpoint, entries: [LogEntry] = []) -> Bool {
        guard a.nodePk == b.nodePk, a.isSigned, b.isSigned, a != b else { return false }
        if a.seq == b.seq { return true }
        let (earlier, later) = a.seq < b.seq ? (a, b) : (b, a)
        guard UInt64(entries.count) == later.size else { return false }
        let leaves = entries.map(\.leaf)
        let earlierMatches = MMR(leaves: Array(leaves.prefix(Int(earlier.size)))).peaks == earlier.mmrPeaks
            && entries[Int(earlier.seq)] == earlier.entry
        let laterMatches = MMR(leaves: leaves).peaks == later.mmrPeaks && entries.last == later.entry
        // The entries reproduce the later checkpoint but not the earlier: the
        // node signed an earlier history its later log doesn't contain.
        return laterMatches && !earlierMatches
    }
}
