import ConvoFoundation

/// Appendix A.3: a binary tree over leaves in order. Leaf = `H(tag ‖
/// bytes)` (the caller hashes leaves); inner = `H("convo/node" ‖ left ‖
/// right)`; an odd last node is promoted unchanged; the empty set's root is
/// `H("convo/leaf")`. Inclusion proofs are `(sibling, side)` pairs from
/// leaf to root, side 0 = the sibling is on the left, 1 = on the right.
public enum Merkle {
    public struct ProofStep: Hashable, Sendable, BorshCodable {
        public let sibling: Hash32
        /// 0: sibling on the left; 1: sibling on the right.
        public let side: UInt8

        public init(sibling: Hash32, side: UInt8) {
            self.sibling = sibling
            self.side = side
        }

        public func borshEncode(into w: inout BorshWriter) { w.fixed(sibling); w.u8(side) }
        public init(borshFrom r: inout BorshReader) throws { sibling = try r.hash32(); side = try r.u8() }
    }

    public static let emptyRoot = Hashing.hash(Domain.leaf)

    public static func root(leaves: [Hash32], nodeTag: String = Domain.node) -> Hash32 {
        guard !leaves.isEmpty else { return emptyRoot }
        var level = leaves
        while level.count > 1 {
            var next: [Hash32] = []
            next.reserveCapacity((level.count + 1) / 2)
            var i = 0
            while i < level.count {
                if i + 1 < level.count {
                    next.append(Hashing.hash(nodeTag, level[i].bytes, level[i + 1].bytes))
                } else {
                    next.append(level[i])
                }
                i += 2
            }
            level = next
        }
        return level[0]
    }

    /// The inclusion proof for the leaf at `index`.
    public static func proof(leaves: [Hash32], index: Int, nodeTag: String = Domain.node) -> [ProofStep] {
        precondition(index >= 0 && index < leaves.count)
        var steps: [ProofStep] = []
        var level = leaves
        var at = index
        while level.count > 1 {
            var next: [Hash32] = []
            var i = 0
            while i < level.count {
                if i + 1 < level.count {
                    if i == at { steps.append(ProofStep(sibling: level[i + 1], side: 1)) }
                    if i + 1 == at { steps.append(ProofStep(sibling: level[i], side: 0)) }
                    next.append(Hashing.hash(nodeTag, level[i].bytes, level[i + 1].bytes))
                } else {
                    next.append(level[i])   // promoted: no step
                }
                i += 2
            }
            at /= 2
            level = next
        }
        return steps
    }

    public static func verify(leaf: Hash32, proof: [ProofStep], root: Hash32, nodeTag: String = Domain.node) -> Bool {
        var current = leaf
        for step in proof {
            switch step.side {
            case 0: current = Hashing.hash(nodeTag, step.sibling.bytes, current.bytes)
            case 1: current = Hashing.hash(nodeTag, current.bytes, step.sibling.bytes)
            default: return false
            }
        }
        return current == root
    }
}

extension Merkle {
    /// The leaf index a proof's sides imply (sibling on the left ⇒ this
    /// node was the right child ⇒ bit set). Exact for a perfect tree; with
    /// promoted nodes a level has no step, so use `verify(leaf:proof:root:
    /// index:count:)` when the position matters.
    public static func impliedIndex(of proof: [ProofStep]) -> Int {
        var index = 0
        for (level, step) in proof.enumerated() where step.side == 0 { index |= 1 << level }
        return index
    }

    /// The levels at which the leaf at `index` in a tree of `count` leaves
    /// has a sibling (a step), bottom up: at level ℓ the tree has
    /// ⌈count / 2^ℓ⌉ nodes, and node `index >> ℓ` has a sibling when the
    /// partner position exists. Returns the side each step must show.
    public static func shape(index: Int, count: Int) -> [UInt8]? {
        guard index >= 0, index < count, count > 0 else { return nil }
        var sides: [UInt8] = []
        var nodes = count
        var p = index
        while nodes > 1 {
            if (p ^ 1) < nodes { sides.append(p & 1 == 0 ? 1 : 0) }
            nodes = (nodes + 1) / 2
            p >>= 1
        }
        return sides
    }

    /// Verifies a path and that it is the path of the leaf at `index` in
    /// a tree of exactly `count` leaves: the steps' sides and the levels
    /// without a step are what that shape dictates.
    public static func verify(leaf: Hash32, proof: [ProofStep], root: Hash32, index: Int, count: Int, nodeTag: String = Domain.node) -> Bool {
        guard let sides = shape(index: index, count: count), proof.map(\.side) == sides else { return false }
        return verify(leaf: leaf, proof: proof, root: root, nodeTag: nodeTag)
    }
}
