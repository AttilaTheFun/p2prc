import ConvoFoundation

// §6 and Appendices A.4–A.5: what a node commits, and how an item is
// cited against the node's witnessed log.

/// A.5: the sorted commitment tree. `n` item hashes become `n + 1` gap
/// leaves, each asserting that no item lies strictly between its bounds,
/// so membership and non-membership are both one path.
public enum GapTree {
    public struct Leaf: Hashable, Sendable, BorshCodable {
        public var lo: Hash32
        public var hi: Hash32
        public init(lo: Hash32, hi: Hash32) { self.lo = lo; self.hi = hi }
        /// `H("convo/gap" ‖ lo ‖ hi)`.
        public var hash: Hash32 { Hashing.hash(Domain.gap, lo.bytes, hi.bytes) }
        public func borshEncode(into w: inout BorshWriter) { w.fixed(lo); w.fixed(hi) }
        public init(borshFrom r: inout BorshReader) throws { lo = try r.hash32(); hi = try r.hash32() }
        public func contains(strictly item: Hash32) -> Bool { lo < item && item < hi }
        public func bounds(_ item: Hash32) -> Bool { lo == item || hi == item }
    }

    public static let low = Hash32.zero
    public static let high = Hash32([UInt8](repeating: 0xff, count: 32))

    /// Ascending, without duplicates: the order the leaves are built on.
    public static func sorted(_ items: [Hash32]) -> [Hash32] { Array(Set(items)).sorted() }

    public static func leaves(items: [Hash32]) -> [Leaf] {
        let h = sorted(items)
        var out: [Leaf] = []
        out.reserveCapacity(h.count + 1)
        for i in 0...h.count {
            out.append(Leaf(lo: i == 0 ? low : h[i - 1], hi: i == h.count ? high : h[i]))
        }
        return out
    }

    public static func root(items: [Hash32]) -> Hash32 {
        Merkle.root(leaves: leaves(items: items).map(\.hash), nodeTag: Domain.gapNode)
    }

    public static func proof(items: [Hash32], leafIndex: Int) -> [Merkle.ProofStep] {
        Merkle.proof(leaves: leaves(items: items).map(\.hash), index: leafIndex, nodeTag: Domain.gapNode)
    }

    /// The gap leaf whose upper bound is `item` (membership), with its index.
    public static func membershipLeaf(items: [Hash32], item: Hash32) -> (index: Int, leaf: Leaf)? {
        let all = leaves(items: items)
        guard let i = all.firstIndex(where: { $0.hi == item }) else { return nil }
        return (i, all[i])
    }

    /// The gap leaf strictly around `item` (non-membership), with its index.
    public static func gapLeaf(items: [Hash32], around item: Hash32) -> (index: Int, leaf: Leaf)? {
        let all = leaves(items: items)
        guard let i = all.firstIndex(where: { $0.contains(strictly: item) }) else { return nil }
        return (i, all[i])
    }

    public static func verify(leaf: Leaf, proof: [Merkle.ProofStep], root: Hash32) -> Bool {
        Merkle.verify(leaf: leaf.hash, proof: proof, root: root, nodeTag: Domain.gapNode)
    }

    public static func verifyMembership(item: Hash32, leaf: Leaf, proof: [Merkle.ProofStep], root: Hash32) -> Bool {
        leaf.bounds(item) && verify(leaf: leaf, proof: proof, root: root)
    }

    public static func verifyNonMembership(item: Hash32, leaf: Leaf, proof: [Merkle.ProofStep], root: Hash32) -> Bool {
        leaf.contains(strictly: item) && verify(leaf: leaf, proof: proof, root: root)
    }
}

/// A.4: a proof that a leaf is under one of an MMR's peaks, naming the
/// accumulator size it was made against and the leaf's index (rev2), so
/// a verifier checks the shape before the hashes and an old proof can be
/// re-verified against the accumulator rebuilt at that size.
public struct MmrProof: Hashable, Sendable, BorshCodable {
    public var size: UInt64
    public var leafIndex: UInt64
    public var siblings: [Merkle.ProofStep]
    public var peakIndex: UInt8
    public init(size: UInt64, leafIndex: UInt64, siblings: [Merkle.ProofStep], peakIndex: UInt8) {
        self.size = size; self.leafIndex = leafIndex; self.siblings = siblings; self.peakIndex = peakIndex
    }
    public func borshEncode(into w: inout BorshWriter) {
        w.u64(size); w.u64(leafIndex); w.vec(siblings) { w, s in s.borshEncode(into: &w) }; w.u8(peakIndex)
    }
    public init(borshFrom r: inout BorshReader) throws {
        size = try r.u64(); leafIndex = try r.u64(); siblings = try r.vec { try Merkle.ProofStep(borshFrom: &$0) }; peakIndex = try r.u8()
    }
}

/// A.4: the append-only accumulator over a node's batch leaves. Peaks are
/// the perfect trees of the set bits of the leaf count, left to right.
public struct MMR: Hashable, Sendable {
    public private(set) var leaves: [Hash32] = []
    public init() {}
    public init(leaves: [Hash32]) { self.leaves = leaves }

    /// `H("convo/cbatch-leaf" ‖ root ‖ time ‖ count)`, `time` in unix ms.
    public static func leaf(root: Hash32, time: UInt64, count: UInt64) -> Hash32 {
        var w = BorshWriter(); w.fixed(root); w.u64(time); w.u64(count)
        return Hashing.hash(Domain.commitmentLeaf, w.bytes)
    }

    public var size: UInt64 { UInt64(leaves.count) }

    public mutating func append(_ leaf: Hash32) { leaves.append(leaf) }

    /// The peak ranges for `n` leaves: (start, height), left to right.
    public static func ranges(size n: Int) -> [(start: Int, height: Int)] {
        var out: [(Int, Int)] = []
        var start = 0
        for bit in stride(from: 63, through: 0, by: -1) where n & (1 << bit) != 0 {
            out.append((start, bit))
            start += 1 << bit
        }
        return out
    }

    private static func perfectRoot(_ nodes: ArraySlice<Hash32>) -> Hash32 {
        var level = Array(nodes)
        while level.count > 1 {
            var next: [Hash32] = []
            for i in stride(from: 0, to: level.count, by: 2) { next.append(Hashing.hash(Domain.mmrNode, level[i].bytes, level[i + 1].bytes)) }
            level = next
        }
        return level[0]
    }

    public var peaks: [Hash32] {
        Self.ranges(size: leaves.count).map { r in Self.perfectRoot(leaves[r.start..<(r.start + (1 << r.height))]) }
    }

    /// The proof for leaf `index`.
    public func proof(index: Int) -> MmrProof? {
        let ranges = Self.ranges(size: leaves.count)
        guard let peak = ranges.firstIndex(where: { index >= $0.start && index < $0.start + (1 << $0.height) }) else { return nil }
        let r = ranges[peak]
        var level = Array(leaves[r.start..<(r.start + (1 << r.height))])
        var p = index - r.start
        var steps: [Merkle.ProofStep] = []
        while level.count > 1 {
            let sibling = p ^ 1
            steps.append(Merkle.ProofStep(sibling: level[sibling], side: p & 1 == 0 ? 1 : 0))
            var next: [Hash32] = []
            for i in stride(from: 0, to: level.count, by: 2) { next.append(Hashing.hash(Domain.mmrNode, level[i].bytes, level[i + 1].bytes)) }
            level = next
            p >>= 1
        }
        return MmrProof(size: UInt64(leaves.count), leafIndex: UInt64(index), siblings: steps, peakIndex: UInt8(peak))
    }

    /// Verifies `leaf` under `peaks` for an accumulator of `size` leaves;
    /// returns the leaf's index, which the proof's shape and sides imply.
    public static func verify(leaf: Hash32, proof: MmrProof, peaks: [Hash32], size: UInt64) -> Int? {
        // The size comes off the wire: one no `Int` holds (wasm32's is 32
        // bits) is a miss, not a trap.
        guard proof.size == size, proof.leafIndex < size, let count = Int(exactly: size) else { return nil }
        let ranges = Self.ranges(size: count)
        let peakIndex = Int(proof.peakIndex)
        guard ranges.count == peaks.count, peakIndex < ranges.count else { return nil }
        let r = ranges[peakIndex]
        guard proof.siblings.count == r.height else { return nil }
        guard Merkle.verify(leaf: leaf, proof: proof.siblings, root: peaks[peakIndex], nodeTag: Domain.mmrNode) else { return nil }
        let index = r.start + Merkle.impliedIndex(of: proof.siblings)
        return UInt64(index) == proof.leafIndex ? index : nil
    }
}

/// §6: a node's signed batch of item hashes.
public struct CommitmentBatch: Hashable, Sendable {
    public var nodePk: PublicKey
    public var seq: UInt64
    public var prevRoot: Hash32
    /// Strictly ascending, ≤ BATCH_MAX.
    public var leaves: [Hash32]
    public var signature: [UInt8]

    public init(nodePk: PublicKey, seq: UInt64, prevRoot: Hash32, leaves: [Hash32], signature: [UInt8]) {
        self.nodePk = nodePk; self.seq = seq; self.prevRoot = prevRoot; self.leaves = GapTree.sorted(leaves); self.signature = signature
    }

    public static func sign(nodePk: PublicKey, seq: UInt64, prevRoot: Hash32, leaves: [Hash32], with nodeKey: SigningKey) -> CommitmentBatch {
        let sorted = GapTree.sorted(leaves)
        let root = GapTree.root(items: sorted)
        return CommitmentBatch(nodePk: nodePk, seq: seq, prevRoot: prevRoot, leaves: sorted,
                               signature: nodeKey.sign(preimage(nodePk: nodePk, seq: seq, prevRoot: prevRoot, root: root)))
    }

    public var root: Hash32 { GapTree.root(items: leaves) }
    public var count: UInt64 { UInt64(leaves.count) }

    /// `H("convo/cbatch" ‖ node_pk ‖ seq ‖ prev_root ‖ root)`.
    public static func preimage(nodePk: PublicKey, seq: UInt64, prevRoot: Hash32, root: Hash32) -> Hash32 {
        var w = BorshWriter(); w.fixed(nodePk); w.u64(seq); w.fixed(prevRoot); w.fixed(root)
        return Hashing.hash(Domain.commitmentBatch, w.bytes)
    }

    public var isValid: Bool {
        leaves == GapTree.sorted(leaves) && Signature.verify(signature, hash: Self.preimage(nodePk: nodePk, seq: seq, prevRoot: prevRoot, root: root), publicKey: nodePk)
    }

    public var wire: [UInt8] {
        var w = BorshWriter(); w.fixed(nodePk); w.u64(seq); w.fixed(prevRoot); w.vec(leaves) { w, l in w.fixed(l) }
        return w.bytes + signature
    }

    public static func fromWire(_ bytes: [UInt8]) throws -> CommitmentBatch {
        guard bytes.count > 64 else { throw BorshError("batch too short") }
        var r = BorshReader(Array(bytes.dropLast(64)))
        let batch = CommitmentBatch(nodePk: try r.hash32(), seq: try r.u64(), prevRoot: try r.hash32(),
                                    leaves: try r.vec { try $0.hash32() }, signature: Array(bytes.suffix(64)))
        try r.finish()
        return batch
    }

    /// The `CommitmentRef` for an item of this batch, given the batch's
    /// time, the node's log, and a witnessed checkpoint of it.
    public func reference(item: Hash32, time: UInt64, mmr: MMR, checkpoint: WitnessedCheckpoint) -> CommitmentRef? {
        guard let (index, leaf) = GapTree.membershipLeaf(items: leaves, item: item),
              checkpoint.checkpoint.size <= mmr.size,
              let batchProof = MMR(leaves: Array(mmr.leaves.prefix(Int(checkpoint.checkpoint.size)))).proof(index: Int(seq))
        else { return nil }
        return CommitmentRef(nodePk: nodePk, batchSeq: seq, batchRoot: root, count: count, time: time, itemHash: item,
                             neighbor: leaf.lo, itemProof: GapTree.proof(items: leaves, leafIndex: index),
                             batchProof: batchProof, checkpoint: checkpoint)
    }
}

/// §6: how an item's commitment is cited. Carries the batch root, count and
/// time (which the log's leaf is over), the gap leaf's other bound, and a
/// witnessed checkpoint of the log, so it resolves on its own.
public struct CommitmentRef: Hashable, Sendable, BorshCodable {
    public var nodePk: PublicKey
    public var batchSeq: UInt64
    public var batchRoot: Hash32
    public var count: UInt64
    /// The batch's time (unix ms), as its checkpoint has it.
    public var time: UInt64
    public var itemHash: Hash32
    /// The gap leaf's other bound (`lo` when the item is its `hi`, else `hi`).
    public var neighbor: Hash32
    public var itemProof: [Merkle.ProofStep]
    /// The batch's leaf against `checkpoint`'s peaks.
    public var batchProof: MmrProof
    /// A witnessed checkpoint of the node's log, at or after the batch.
    public var checkpoint: WitnessedCheckpoint

    public init(nodePk: PublicKey, batchSeq: UInt64, batchRoot: Hash32, count: UInt64, time: UInt64, itemHash: Hash32,
                neighbor: Hash32, itemProof: [Merkle.ProofStep], batchProof: MmrProof, checkpoint: WitnessedCheckpoint) {
        self.nodePk = nodePk; self.batchSeq = batchSeq; self.batchRoot = batchRoot; self.count = count; self.time = time
        self.itemHash = itemHash; self.neighbor = neighbor; self.itemProof = itemProof; self.batchProof = batchProof
        self.checkpoint = checkpoint
    }

    public var gapLeaf: GapTree.Leaf { neighbor < itemHash ? GapTree.Leaf(lo: neighbor, hi: itemHash) : GapTree.Leaf(lo: itemHash, hi: neighbor) }
    public var mmrLeaf: Hash32 { MMR.leaf(root: batchRoot, time: time, count: count) }

    /// The item existed, held by this node, no later than the witnesses'
    /// cosigning: the checkpoint is the node's and carries `witnessQuorum`
    /// independent cosignatures, the batch is in the log it describes, and
    /// the item is a leaf of the batch.
    public func resolves(witnessQuorum: Int = Parameters.Client.witnessQuorum) -> Bool {
        guard checkpoint.checkpoint.nodePk == nodePk, checkpoint.isPublished(quorum: witnessQuorum) else { return false }
        return resolves(peaks: checkpoint.checkpoint.mmrPeaks, size: checkpoint.checkpoint.size)
    }

    /// The batch is in the log of `size` batches with these peaks, and the
    /// item is a leaf of it.
    public func resolves(peaks: [Hash32], size: UInt64) -> Bool {
        guard MMR.verify(leaf: mmrLeaf, proof: batchProof, peaks: peaks, size: size) == Int(batchSeq) else { return false }
        return GapTree.verifyMembership(item: itemHash, leaf: gapLeaf, proof: itemProof, root: batchRoot)
    }

    public func borshEncode(into w: inout BorshWriter) {
        w.fixed(nodePk); w.u64(batchSeq); w.fixed(batchRoot); w.u64(count); w.u64(time); w.fixed(itemHash); w.fixed(neighbor)
        w.vec(itemProof) { w, s in s.borshEncode(into: &w) }
        batchProof.borshEncode(into: &w)
        checkpoint.borshEncode(into: &w)
    }

    public init(borshFrom r: inout BorshReader) throws {
        nodePk = try r.hash32(); batchSeq = try r.u64(); batchRoot = try r.hash32(); count = try r.u64(); time = try r.u64()
        itemHash = try r.hash32(); neighbor = try r.hash32()
        itemProof = try r.vec { try Merkle.ProofStep(borshFrom: &$0) }
        batchProof = try MmrProof(borshFrom: &r)
        checkpoint = try WitnessedCheckpoint(borshFrom: &r)
    }
}
