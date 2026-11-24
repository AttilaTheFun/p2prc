import ConvoCore
import ConvoMLS
import Crypto
import Foundation

/// §2's genesis handshake over MLS, as frames any transport can carry
/// (a data channel, or a node's rendezvous boxes, Part III). The creator
/// builds the MLS group from everyone's KeyPackage and sends the commit
/// in an `invite`; each member applies it, derives `gk`, and answers a
/// sealed `announce`; the creator fixes the genesis and sends it sealed;
/// members of a parent group add a `carry` signature for `create_group`.
public enum HandshakeFrame {
    public static let invite: UInt8 = 0, announce: UInt8 = 1, genesis: UInt8 = 2, carry: UInt8 = 3

    /// What the creator proposes before the members are known. For a
    /// fork it carries the parent attestation the `ParentRef` cites, so
    /// members can check it is over the fork point and signed by a parent
    /// member (§9.3) before they announce.
    public struct Proposal: Sendable, Hashable, BorshCodable {
        public var quorum: UInt8
        public var maxParents: UInt8
        public var maxPayload: UInt32
        public var maxUncommittedRepublish: UInt8
        public var homeNodes: [Hash32]
        public var parent: ParentRef?
        public var parentAttestation: SignedAttestation?
        public var reason: Genesis.Reason

        public init(quorum: UInt8, maxParents: UInt8, maxPayload: UInt32, maxUncommittedRepublish: UInt8,
                    homeNodes: [Hash32], parent: ParentRef? = nil, parentAttestation: SignedAttestation? = nil, reason: Genesis.Reason = .root) {
            self.quorum = quorum; self.maxParents = maxParents; self.maxPayload = maxPayload
            self.maxUncommittedRepublish = maxUncommittedRepublish; self.homeNodes = homeNodes; self.parent = parent
            self.parentAttestation = parentAttestation; self.reason = reason
        }

        public static func defaults(members: Int, homeNodes: [Hash32], parent: ParentRef? = nil, parentAttestation: SignedAttestation? = nil, reason: Genesis.Reason = .root) -> Proposal {
            let d = Parameters.GenesisDefaults.forMembers(members)
            return Proposal(quorum: d.quorum, maxParents: d.maxParents, maxPayload: d.maxPayload,
                            maxUncommittedRepublish: d.maxUncommittedRepublish, homeNodes: homeNodes, parent: parent, parentAttestation: parentAttestation, reason: reason)
        }

        public func borshEncode(into w: inout BorshWriter) {
            w.u8(quorum); w.u8(maxParents); w.u32(maxPayload); w.u8(maxUncommittedRepublish)
            w.vec(homeNodes) { w, n in w.fixed(n) }
            w.option(parent) { w, p in p.borshEncode(into: &w) }
            w.option(parentAttestation) { w, a in w.vec(a.wire) }
            w.u8(reason.rawValue)
        }
        public init(borshFrom r: inout BorshReader) throws {
            quorum = try r.u8(); maxParents = try r.u8(); maxPayload = try r.u32(); maxUncommittedRepublish = try r.u8()
            homeNodes = try r.vec { try $0.hash32() }
            parent = try r.option { try ParentRef(borshFrom: &$0) }
            parentAttestation = try r.option { try SignedAttestation.fromWire(try $0.vec()) }
            reason = Genesis.Reason(rawValue: try r.u8()) ?? .other
        }

        /// §9.3 parent verification, as far as the handshake can take it:
        /// the cited attestation is over the fork point and signed by a
        /// parent member (when the parent's members are known). Whether
        /// the `CommitmentRef` resolves is checked against its witnessed
        /// checkpoint by the client.
        public func parentIsConsistent(parentMembers: [PublicKey]?) -> Bool {
            guard let parent else { return parentAttestation == nil }
            guard let att = parentAttestation, att.attestation.head == parent.head, att.attestation.groupID == parent.groupID,
                  att.itemHash == parent.source.itemHash else { return false }
            if let parentMembers {
                guard Int(att.attestation.signerIdx) < parentMembers.count, att.verify(signer: parentMembers[Int(att.attestation.signerIdx)]) else { return false }
            }
            return true
        }
    }

    public enum Failure: Error, Equatable {
        case badFrame, notInvited, wrongSalt, unexpected, hostBounds(Int), indexMismatch, notComplete, badCarry, badParent, expiredKeyPackage
    }
}

/// The creator's side. Not Sendable: it owns an MLS group until the
/// session takes it.
public final class HandshakeCreator {
    public let identity: ConvoIdentity
    public let salt: Hash32
    public let roster: [KeyPackage]
    public let proposal: HandshakeFrame.Proposal
    private let mls: MLSGroup
    private let commitPayload: [UInt8]
    private var announced: [(identity: PublicKey, gk: PublicKey)] = []
    public private(set) var genesis: Genesis?
    public private(set) var carrySigs: [(UInt8, [UInt8])] = []
    /// Carry signatures are checked against the parent's members.
    public var parentMembers: [PublicKey] = []

    /// `roster` lists every member's KeyPackage; the creator's own must be
    /// among them and is moved to index 0.
    public init(identity: ConvoIdentity, roster: [KeyPackage], proposal: HandshakeFrame.Proposal, salt: Hash32 = Hash32((0..<32).map { _ in UInt8.random(in: 0...255) })) throws {
        guard let own = roster.first(where: { $0.body.identityPk == identity.publicKey }) else { throw HandshakeFrame.Failure.notInvited }
        self.identity = identity
        self.salt = salt
        self.roster = [own] + roster.filter { $0.body.identityPk != identity.publicKey }
        self.proposal = proposal
        guard proposal.parentIsConsistent(parentMembers: nil) else { throw HandshakeFrame.Failure.badParent }
        mls = MLSGroup(groupID: salt.hex, selfID: identity.publicKey.hex, selfKey: identity.hpkeKey(index: own.body.hpkeIndex))
        let commit = try mls.createCommit(id: identity.publicKey.hex, roster: self.roster.map(\.mlsMember))
        try mls.apply(commit, isOwn: true)
        commitPayload = GroupPayload.encode(commit)
    }

    /// Everything needed to continue later (a CLI runs one command per
    /// process): the MLS commit secret included, so keep it private.
    public var snapshot: [UInt8] {
        var w = BorshWriter()
        w.fixed(salt)
        w.vec(roster) { w, k in w.vec(k.wire) }
        w.vec(commitPayload)
        proposal.borshEncode(into: &w)
        w.vec(mls.lastCommitSecret.map { $0.withUnsafeBytes { Array($0) } } ?? [])
        w.u32(mls.ownGeneration)
        w.vec(announced) { w, a in w.fixed(a.identity); w.fixed(a.gk) }
        w.vec(carrySigs) { w, c in w.u8(c.0); w.fixed(c.1) }
        w.vec(parentMembers) { w, m in w.fixed(m) }
        w.vec(parentIdentities) { w, m in w.fixed(m) }
        w.option(genesis) { w, g in w.vec(g.borsh) }
        return w.bytes
    }

    public init(snapshot: [UInt8], identity: ConvoIdentity) throws {
        var r = BorshReader(snapshot)
        self.identity = identity
        salt = try r.hash32()
        roster = try r.vec { try KeyPackage.fromWire(try $0.vec()) }
        commitPayload = try r.vec()
        proposal = try HandshakeFrame.Proposal(borshFrom: &r)
        let secret = try r.vec(); let generation = try r.u32()
        announced = try r.vec { r in (try r.hash32(), try r.hash32()) }
        carrySigs = try r.vec { r in (try r.u8(), try r.fixed(64)) }
        parentMembers = try r.vec { try $0.hash32() }
        parentIdentities = try r.vec { try $0.hash32() }
        genesis = try r.option { try Genesis.decode(try $0.vec()) }
        try r.finish()
        let ownIndex = roster.first { $0.body.identityPk == identity.publicKey }?.body.hpkeIndex ?? 0
        mls = MLSGroup(groupID: salt.hex, selfID: identity.publicKey.hex, selfKey: identity.hpkeKey(index: ownIndex))
        mls.restore(epoch: 1, commitSecret: SymmetricKey(data: secret), roster: roster.map(\.mlsMember), ownGeneration: generation)
    }

    /// The same invite goes to every member.
    public func invite() -> [UInt8] {
        var w = BorshWriter()
        w.u8(HandshakeFrame.invite); w.fixed(salt)
        w.vec(roster) { w, k in w.vec(k.wire) }
        w.vec(commitPayload)
        proposal.borshEncode(into: &w)
        return w.bytes
    }

    public var isComplete: Bool { announced.count == roster.count - 1 }

    /// Feeds a member's frame. Returns the sealed genesis frame once the
    /// last member has announced (send it to everyone), else nil.
    public func receive(_ frame: [UInt8]) throws -> [UInt8]? {
        var r = BorshReader(frame)
        switch try r.u8() {
        case HandshakeFrame.announce:
            let who = try r.hash32()
            let sealed = try GroupPayload.decodeSealed(try r.vec())
            try r.finish()
            guard sealed.sender == who.hex, roster.dropFirst().contains(where: { $0.body.identityPk == who }) else { throw HandshakeFrame.Failure.notInvited }
            let text = try mls.open(sealed)
            guard text.hasPrefix("gk-announce:"), let gk = Hash32(hex: String(text.dropFirst("gk-announce:".count))) else { throw HandshakeFrame.Failure.badFrame }
            if !announced.contains(where: { $0.identity == who }) { announced.append((who, gk)) }
            guard isComplete, genesis == nil else { return nil }
            let members = [identity.groupKey(salt: salt).publicKey] + announced.map(\.gk)
            let g = Genesis(salt: salt, members: members, quorum: proposal.quorum, maxParents: proposal.maxParents,
                            maxPayload: proposal.maxPayload, maxUncommittedRepublish: proposal.maxUncommittedRepublish, homeNodes: proposal.homeNodes,
                            parent: proposal.parent, carry: carryPairs(), reason: proposal.reason)
            genesis = g
            var w = BorshWriter()
            w.u8(HandshakeFrame.genesis)
            w.vec(GroupPayload.encode(try mls.seal("genesis:" + g.borsh.hex)))
            w.vec(orderedIdentities) { w, i in w.fixed(i) }
            return w.bytes
        case HandshakeFrame.carry:
            let idx = try r.u8(); let sig = try r.fixed(64)
            try r.finish()
            guard let g = genesis, Int(idx) < parentMembers.count, let ref = g.parent,
                  Signature.verify(sig, hash: ForkAuthorization.preimage(parent: ref.groupID, child: g.groupID), publicKey: parentMembers[Int(idx)]) else {
                throw HandshakeFrame.Failure.badCarry
            }
            if !carrySigs.contains(where: { $0.0 == idx }) { carrySigs.append((idx, sig)) }
            return nil
        default:
            throw HandshakeFrame.Failure.unexpected
        }
    }

    /// Identities in genesis member order.
    public var orderedIdentities: [PublicKey] { [identity.publicKey] + announced.map(\.identity) }

    /// (parent_idx, child_idx) for identities in both, from `parentIdentities`
    /// (the parent roster's identity keys in parent member order).
    public var parentIdentities: [PublicKey] = []
    private func carryPairs() -> [(UInt8, UInt8)] {
        guard proposal.parent != nil else { return [] }
        var pairs: [(UInt8, UInt8)] = []
        for (childIdx, id) in orderedIdentities.enumerated() {
            if let parentIdx = parentIdentities.firstIndex(of: id) { pairs.append((UInt8(parentIdx), UInt8(childIdx))) }
        }
        return pairs
    }

    /// The session, once the genesis frame has been produced. Consumes
    /// the MLS group.
    public func session() throws -> sending GroupState {
        guard let genesis else { throw HandshakeFrame.Failure.notComplete }
        let ordered = orderedIdentities.map { id in roster.first { $0.body.identityPk == id }! }
        guard let secret = mls.lastCommitSecret else { throw HandshakeFrame.Failure.notComplete }
        return try GroupState(genesis: genesis, roster: ordered, identity: identity,
                                commitSecret: secret.withUnsafeBytes { Array($0) }, ownGeneration: mls.ownGeneration)
    }
}

/// An invited member's side.
public final class HandshakeJoiner {
    public let identity: ConvoIdentity
    public private(set) var salt: Hash32?
    public private(set) var roster: [KeyPackage] = []
    public private(set) var proposal: HandshakeFrame.Proposal?
    public private(set) var genesis: Genesis?
    private var mls: MLSGroup?
    private var orderedRoster: [KeyPackage] = []
    public var minTotalHosts = Parameters.Client.minTotalHosts
    public var maxTotalHosts = Parameters.Client.maxTotalHosts
    /// The parent's members when this identity is in the parent, so the
    /// invite's cited attestation can be checked (§9.3).
    public var parentMembers: [PublicKey]?

    public init(identity: ConvoIdentity) { self.identity = identity }

    public var snapshot: [UInt8] {
        var w = BorshWriter()
        w.option(salt) { w, s in w.fixed(s) }
        w.vec(roster) { w, k in w.vec(k.wire) }
        w.option(proposal) { w, p in p.borshEncode(into: &w) }
        w.vec(mls?.lastCommitSecret.map { $0.withUnsafeBytes { Array($0) } } ?? [])
        w.u32(mls?.ownGeneration ?? 0)
        w.option(genesis) { w, g in w.vec(g.borsh) }
        w.vec(orderedRoster) { w, k in w.vec(k.wire) }
        return w.bytes
    }

    public init(snapshot: [UInt8], identity: ConvoIdentity) throws {
        self.identity = identity
        var r = BorshReader(snapshot)
        salt = try r.option { try $0.hash32() }
        roster = try r.vec { try KeyPackage.fromWire(try $0.vec()) }
        proposal = try r.option { try HandshakeFrame.Proposal(borshFrom: &$0) }
        let secret = try r.vec(); let generation = try r.u32()
        genesis = try r.option { try Genesis.decode(try $0.vec()) }
        orderedRoster = try r.vec { try KeyPackage.fromWire(try $0.vec()) }
        try r.finish()
        if let salt, !secret.isEmpty {
            let ownIndex = roster.first { $0.body.identityPk == identity.publicKey }?.body.hpkeIndex ?? 0
            let group = MLSGroup(groupID: salt.hex, selfID: identity.publicKey.hex, selfKey: identity.hpkeKey(index: ownIndex))
            group.restore(epoch: 1, commitSecret: SymmetricKey(data: secret), roster: roster.map(\.mlsMember), ownGeneration: generation)
            mls = group
        }
    }

    /// Feeds a creator's frame. An invite yields the announce frame to
    /// send back; the genesis frame yields nil and `genesis` is set.
    public func receive(_ frame: [UInt8]) throws -> [UInt8]? {
        var r = BorshReader(frame)
        switch try r.u8() {
        case HandshakeFrame.invite:
            let salt = try r.hash32()
            let roster = try r.vec { try KeyPackage.fromWire(try $0.vec()) }
            let commit = try GroupPayload.decodeCommit(try r.vec())
            let proposal = try HandshakeFrame.Proposal(borshFrom: &r)
            try r.finish()
            guard let own = roster.first(where: { $0.body.identityPk == identity.publicKey }) else { throw HandshakeFrame.Failure.notInvited }
            guard (minTotalHosts...maxTotalHosts).contains(proposal.homeNodes.count) else { throw HandshakeFrame.Failure.hostBounds(proposal.homeNodes.count) }
            guard proposal.parentIsConsistent(parentMembers: parentMembers) else { throw HandshakeFrame.Failure.badParent }
            let group = MLSGroup(groupID: salt.hex, selfID: identity.publicKey.hex, selfKey: identity.hpkeKey(index: own.body.hpkeIndex))
            guard case .applied = try group.apply(commit) else { throw HandshakeFrame.Failure.badFrame }
            self.salt = salt; self.roster = roster; self.proposal = proposal; self.mls = group
            let gk = identity.groupKey(salt: salt).publicKey
            var w = BorshWriter()
            w.u8(HandshakeFrame.announce); w.fixed(identity.publicKey)
            w.vec(GroupPayload.encode(try group.seal("gk-announce:" + gk.hex)))
            return w.bytes
        case HandshakeFrame.genesis:
            guard let mls, let salt else { throw HandshakeFrame.Failure.unexpected }
            let sealed = try GroupPayload.decodeSealed(try r.vec())
            let order = try r.vec { try $0.hash32() }
            try r.finish()
            let text = try mls.open(sealed)
            guard text.hasPrefix("genesis:"), let bytes = [UInt8](hex: String(text.dropFirst("genesis:".count))) else { throw HandshakeFrame.Failure.badFrame }
            let g = try Genesis.decode(bytes)
            guard g.salt == salt else { throw HandshakeFrame.Failure.wrongSalt }
            let gk = identity.groupKey(salt: salt).publicKey
            guard let myIdx = order.firstIndex(of: identity.publicKey), myIdx < g.members.count, g.members[myIdx] == gk else { throw HandshakeFrame.Failure.indexMismatch }
            guard let p = proposal, g.homeNodes == p.homeNodes, order.count == g.members.count else { throw HandshakeFrame.Failure.badFrame }
            let ordered = try order.map { id in
                guard let k = roster.first(where: { $0.body.identityPk == id }) else { throw HandshakeFrame.Failure.badFrame }
                return k
            }
            genesis = g
            orderedRoster = ordered
            return nil
        default:
            throw HandshakeFrame.Failure.unexpected
        }
    }

    /// A carry frame for the creator, when this identity is `parentIdx`
    /// in the parent group (signed with the parent's group key).
    public func carry(parentIdx: UInt8, parentKey: SigningKey) throws -> [UInt8] {
        guard let genesis, let ref = genesis.parent else { throw HandshakeFrame.Failure.notComplete }
        var w = BorshWriter()
        w.u8(HandshakeFrame.carry); w.u8(parentIdx)
        w.fixed(parentKey.sign(ForkAuthorization.preimage(parent: ref.groupID, child: genesis.groupID)))
        return w.bytes
    }

    public func session() throws -> sending GroupState {
        guard let genesis, let mls, let secret = mls.lastCommitSecret else { throw HandshakeFrame.Failure.notComplete }
        self.mls = nil
        return try GroupState(genesis: genesis, roster: orderedRoster, identity: identity,
                                commitSecret: secret.withUnsafeBytes { Array($0) }, ownGeneration: mls.ownGeneration)
    }
}

extension KeyPackage {
    /// The MLS roster entry: identity key as the stable member id.
    public var mlsMember: MLSGroup.Member { MLSGroup.Member(id: body.identityPk.hex, name: body.name, publicKey: Data(body.hpkePk)) }
}
