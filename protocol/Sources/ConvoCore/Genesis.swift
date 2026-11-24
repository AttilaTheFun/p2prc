import ConvoFoundation

/// §2: a group's immutable founding record. `group_id = H("convo/genesis" ‖ borsh(Genesis))`.
public struct Genesis: Hashable, Sendable, BorshCodable {
    public static let currentVersion: UInt8 = 3

    public enum Reason: UInt8, Sendable {
        case root = 0, membership = 1, recovery = 2, keyRotation = 3, other = 4, hostChange = 5
    }

    public var version: UInt8
    /// Random; also the MLS group_id.
    public var salt: Hash32
    /// gk pubkeys; index = member_idx.
    public var members: [Hash32]
    /// Attestations that make a head `attested` (§5).
    public var quorum: UInt8
    public var maxParents: UInt8
    /// Bytes.
    public var maxPayload: UInt32
    public var maxUncommittedRepublish: UInt8
    /// Registered node pubkeys, 1…16 (§13.1): where members write and read.
    public var homeNodes: [Hash32]
    public var parent: ParentRef?
    /// (parent_idx, child_idx) for identities in both.
    public var carry: [(UInt8, UInt8)]
    public var reason: UInt8

    public init(version: UInt8 = Genesis.currentVersion, salt: Hash32, members: [Hash32], quorum: UInt8,
                maxParents: UInt8, maxPayload: UInt32, maxUncommittedRepublish: UInt8, homeNodes: [Hash32],
                parent: ParentRef? = nil, carry: [(UInt8, UInt8)] = [], reason: Reason = .root) {
        self.version = version
        self.salt = salt
        self.members = members
        self.quorum = quorum
        self.maxParents = maxParents
        self.maxPayload = maxPayload
        self.maxUncommittedRepublish = maxUncommittedRepublish
        self.homeNodes = homeNodes
        self.parent = parent
        self.carry = carry
        self.reason = reason.rawValue
    }

    public var groupID: Hash32 { Hashing.hash(Domain.genesis, borsh) }

    public func borshEncode(into w: inout BorshWriter) {
        w.u8(version)
        w.fixed(salt)
        w.vec(members) { w, m in w.fixed(m) }
        w.u8(quorum)
        w.u8(maxParents)
        w.u32(maxPayload)
        w.u8(maxUncommittedRepublish)
        w.vec(homeNodes) { w, n in w.fixed(n) }
        w.option(parent) { w, p in p.borshEncode(into: &w) }
        w.vec(carry) { w, c in w.u8(c.0); w.u8(c.1) }
        w.u8(reason)
    }

    public init(borshFrom r: inout BorshReader) throws {
        version = try r.u8()
        salt = try r.hash32()
        members = try r.vec { try $0.hash32() }
        quorum = try r.u8()
        maxParents = try r.u8()
        maxPayload = try r.u32()
        maxUncommittedRepublish = try r.u8()
        homeNodes = try r.vec { try $0.hash32() }
        parent = try r.option { try ParentRef(borshFrom: &$0) }
        carry = try r.vec { r in (try r.u8(), try r.u8()) }
        reason = try r.u8()
    }

    // Hashable over the canonical bytes (tuples are not Hashable).
    public static func == (a: Genesis, b: Genesis) -> Bool { a.borsh == b.borsh }
    public func hash(into hasher: inout Hasher) { hasher.combine(borsh) }
}

/// A child's pointer to its fork point in the parent: a message hash and
/// a `CommitmentRef` to a committed parent attestation on it (§9.1).
public struct ParentRef: Hashable, Sendable, BorshCodable {
    public var groupID: Hash32
    public var head: Hash32
    public var source: CommitmentRef

    public init(groupID: Hash32, head: Hash32, source: CommitmentRef) {
        self.groupID = groupID
        self.head = head
        self.source = source
    }

    public func borshEncode(into w: inout BorshWriter) {
        w.fixed(groupID); w.fixed(head); source.borshEncode(into: &w)
    }

    public init(borshFrom r: inout BorshReader) throws {
        groupID = try r.hash32(); head = try r.hash32(); source = try CommitmentRef(borshFrom: &r)
    }
}

/// §9.3: the carry signature's preimage and the official-child rule.
public enum ForkAuthorization {
    /// `H("convo/fork" ‖ parent_group_id ‖ child_group_id)`.
    public static func preimage(parent: Hash32, child: Hash32) -> Hash32 {
        Hashing.hash(Domain.fork, parent.bytes, child.bytes)
    }

    /// `min(parent.quorum, |carry|)`, at least 1.
    public static func threshold(parentQuorum: UInt8, carryCount: Int) -> Int {
        max(1, min(Int(parentQuorum), carryCount))
    }

    /// The parent indices whose carry signatures verify.
    public static func verify(child: Genesis, parentMembers: [PublicKey], carrySigs: [(UInt8, [UInt8])]) -> Set<UInt8> {
        guard let ref = child.parent else { return [] }
        let hash = preimage(parent: ref.groupID, child: child.groupID)
        var ok: Set<UInt8> = []
        for (idx, sig) in carrySigs where child.carry.contains(where: { $0.0 == idx }) && Int(idx) < parentMembers.count {
            if Signature.verify(sig, hash: hash, publicKey: parentMembers[Int(idx)]) { ok.insert(idx) }
        }
        return ok
    }

    public static func isOfficial(child: Genesis, parentQuorum: UInt8, parentMembers: [PublicKey], carrySigs: [(UInt8, [UInt8])]) -> Bool {
        verify(child: child, parentMembers: parentMembers, carrySigs: carrySigs).count >= threshold(parentQuorum: parentQuorum, carryCount: child.carry.count)
    }
}
