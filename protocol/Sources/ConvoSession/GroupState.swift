import ConvoCore
import ConvoMLS
import ConvoNet
import Crypto
import Foundation

/// One group as a member sees it: the genesis, the DAG, the receipts and
/// commitments its items have, the MLS group, and this member's keys.
/// Every mutation is a pure Part I rule; delivery is a client's job.
/// Synchronous and not actor-isolated, so hosts without Swift concurrency
/// (the browser) can drive it; `GroupSession` wraps it for the rest.
public final class GroupState {
    public struct Entry: Sendable, Hashable {
        public let hash: Hash32
        public let authorIdx: UInt8
        public let seq: UInt64
        public let ts: UInt64
        public let kind: Message.Kind
        public let text: String?
        public let state: MessageState
        /// For a republish (§9.4): the original author and whether the
        /// proof verified; nil until its source has been checked.
        public let republished: (original: UInt8, verified: Bool?)?
        /// Kinds 3 and 4, opened.
        public var reaction: Reaction? = nil
        public var attachment: Attachment? = nil

        public static func == (a: Entry, b: Entry) -> Bool { a.hash == b.hash }
        public func hash(into hasher: inout Hasher) { hasher.combine(hash) }
    }

    public let genesis: Genesis
    public let groupID: Hash32
    public let identity: ConvoIdentity
    public let groupKey: SigningKey
    public let memberIdx: UInt8
    public private(set) var dag: DAG
    public let roster: [KeyPackage]
    private let mls: MLSGroup
    private var opened: [Hash32: String] = [:]
    /// Kinds 3 and 4 as opened (`Content.swift`), by message hash.
    public private(set) var reactions: [Hash32: Reaction] = [:]
    public private(set) var attachments: [Hash32: Attachment] = [:]
    private var republishes: [Hash32: Republish] = [:]
    private var republishVerdicts: [Hash32: Bool] = [:]
    private var nextSeq: UInt64 = 0
    /// Items receipted per node: `(node → item → receipt)`, kept until the
    /// item is committed and `retain_until` has passed.
    public private(set) var receipts: [PublicKey: [Hash32: Receipt]] = [:]
    /// The first `CommitmentRef` that resolved for each item (§6).
    public private(set) var commitments: [Hash32: CommitmentRef] = [:]
    /// Hosts added in band (§13.1) on top of `genesis.homeNodes`.
    public private(set) var extraHosts: [PublicKey] = []
    /// The parent's members, for judging republishes (§9.4).
    public private(set) var parentMembers: [PublicKey] = []
    /// Sources the client has resolved itself (against a later checkpoint
    /// of the node's log, say); judged as resolved. A source that resolves
    /// against its own witnessed checkpoint needs nothing more.
    public private(set) var resolvedSources: Set<CommitmentRef> = []
    public func markResolved(_ ref: CommitmentRef) { resolvedSources.insert(ref); rejudge() }
    /// Sources of held republishes not yet judged resolved.
    public var unresolvedSources: [CommitmentRef] {
        republishes.values.map(\.source).filter { !resolvedSources.contains($0) && !$0.resolves() }
    }
    /// Cadence bookkeeping (§5): what this member attested last.
    public private(set) var lastAttestedHead: Hash32?
    public private(set) var lastAttestedCount: UInt64 = 0
    /// Unix ms.
    public private(set) var lastAttestTime: UInt64 = 0
    private var ownMessagesSinceUpdate = 0
    /// When (message time, ms) this member last issued an Update commit, or
    /// first spoke in the epoch; `MLS_UPDATE_INTERVAL` counts from here.
    public private(set) var lastEpochUpdate: UInt64 = 0

    public enum Failure: Error, Equatable { case notAMember, mlsNotReady, badPayload, wrongGroup, notCommitted }

    private init(genesis: Genesis, roster: [KeyPackage], identity: ConvoIdentity, mls: MLSGroup) throws {
        self.genesis = genesis
        self.groupID = genesis.groupID
        self.identity = identity
        let gk = identity.groupKey(salt: genesis.salt)
        guard let idx = genesis.members.firstIndex(of: gk.publicKey) else { throw Failure.notAMember }
        guard roster.count == genesis.members.count else { throw Failure.notAMember }
        self.groupKey = gk
        self.memberIdx = UInt8(idx)
        self.roster = roster
        self.dag = DAG(genesis: genesis)
        self.mls = mls
    }

    /// Restores from storage: the MLS epoch from its commit secret.
    public convenience init(genesis: Genesis, roster: [KeyPackage], identity: ConvoIdentity, commitSecret: [UInt8], ownGeneration: UInt32, epoch: UInt64 = 1,
                            updatedAt: UInt64 = 0) throws {
        let own = roster.first { $0.body.identityPk == identity.publicKey }
        let mls = MLSGroup(groupID: genesis.salt.hex, selfID: identity.publicKey.hex, selfKey: identity.hpkeKey(index: own?.body.hpkeIndex ?? 0))
        mls.restore(epoch: epoch, commitSecret: SymmetricKey(data: commitSecret), roster: roster.map(\.mlsMember), ownGeneration: ownGeneration)
        try self.init(genesis: genesis, roster: roster, identity: identity, mls: mls)
        lastEpochUpdate = updatedAt
    }

    /// What storage needs to restore the MLS state.
    public var mlsState: (commitSecret: [UInt8], ownGeneration: UInt32, epoch: UInt64, updatedAt: UInt64)? {
        guard let secret = mls.lastCommitSecret else { return nil }
        return (secret.withUnsafeBytes { Array($0) }, mls.ownGeneration, mls.epoch, lastEpochUpdate)
    }

    // MARK: reading

    public var hosts: [PublicKey] { genesis.homeNodes + extraHosts.filter { !genesis.homeNodes.contains($0) } }
    public var identities: [PublicKey] { roster.map(\.body.identityPk) }

    /// The head members attest: the deepest of the DAG's heads, ties by
    /// smallest hash, so concurrent branches join at the next message.
    public var head: Hash32 {
        let heads = dag.heads
        guard !heads.isEmpty else { return groupID }
        return heads.max { a, b in
            let ca = dag.messageCount(under: a), cb = dag.messageCount(under: b)
            return ca < cb || (ca == cb && b < a)
        }!
    }

    public var heads: [Hash32] { dag.heads }
    public var ready: Bool { mls.secrets != nil }
    public var messageCount: UInt64 { head == groupID ? 0 : dag.messageCount(under: head) }

    /// Every message held, over all branches (two members who sent at
    /// once both show), in canonical order.
    public func entries() -> [Entry] {
        let heads = dag.heads
        guard !heads.isEmpty else { return [] }
        return dag.canonicalOrder(under: heads).compactMap { hash in
            guard let m = dag.messages[hash]?.message else { return nil }
            let rp: (UInt8, Bool?)? = republishes[hash].map { ($0.original.authorIdx, republishVerdicts[hash]) }
            var entry = Entry(hash: hash, authorIdx: m.authorIdx, seq: m.seq, ts: m.ts, kind: Message.Kind(rawValue: m.kind) ?? .chat,
                              text: opened[hash], state: dag.state(of: hash), republished: rp)
            entry.reaction = reactions[hash]
            entry.attachment = attachments[hash]
            return entry
        }
    }

    public func message(_ hash: Hash32) -> SignedMessage? { dag.messages[hash] }
    public func contains(_ hash: Hash32) -> Bool { dag.contains(hash) }
    public func state(of hash: Hash32) -> MessageState { dag.state(of: hash) }
    public func republish(_ hash: Hash32) -> Republish? { republishes[hash] }

    // MARK: writing

    public func send(_ text: String, ts: UInt64) throws -> SignedMessage {
        guard mls.secrets != nil else { throw Failure.mlsNotReady }
        let sealed = try mls.seal(text)
        let signed = try append(kind: .chat, payload: GroupPayload.encode(sealed), ts: ts)
        opened[signed.hash] = text
        noteOwnActivity(at: ts)
        return signed
    }

    /// Kind 3: a reaction to `target`, sealed like chat.
    public func sendReaction(to target: Hash32, emoji: String, remove: Bool = false, ts: UInt64) throws -> SignedMessage {
        guard mls.secrets != nil else { throw Failure.mlsNotReady }
        let reaction = Reaction(target: target, emoji: emoji, remove: remove)
        let text = "react:" + reaction.borsh.hex
        let sealed = try mls.seal(text)
        let signed = try append(kind: .reaction, payload: GroupPayload.encode(sealed), ts: ts)
        opened[signed.hash] = text
        reactions[signed.hash] = reaction
        noteOwnActivity(at: ts)
        return signed
    }

    /// Kind 4: an attachment whose sealed bytes the sender has put at the
    /// hosts, sealed like chat.
    public func sendAttachment(_ attachment: Attachment, ts: UInt64) throws -> SignedMessage {
        guard mls.secrets != nil else { throw Failure.mlsNotReady }
        let text = "attach:" + attachment.borsh.hex
        let sealed = try mls.seal(text)
        let signed = try append(kind: .attachment, payload: GroupPayload.encode(sealed), ts: ts)
        opened[signed.hash] = text
        attachments[signed.hash] = attachment
        noteOwnActivity(at: ts)
        return signed
    }

    /// The reactions on `target`, folded in canonical order: per emoji, the
    /// authors whose latest reaction with it was not a removal, in the order
    /// the emojis first appeared.
    public func reactions(on target: Hash32) -> [(emoji: String, authors: [UInt8])] {
        var order: [String] = []
        var authors: [String: [UInt8]] = [:]
        for entry in entries() where entry.kind == .reaction {
            guard let r = entry.reaction, r.target == target else { continue }
            if authors[r.emoji] == nil { order.append(r.emoji); authors[r.emoji] = [] }
            authors[r.emoji]?.removeAll { $0 == entry.authorIdx }
            if !r.remove { authors[r.emoji]?.append(entry.authorIdx) }
        }
        return order.compactMap { emoji in (authors[emoji] ?? []).isEmpty ? nil : (emoji, authors[emoji]!) }
    }

    /// A control message (§3.1): sealed like chat, kept out of the thread.
    public func control(_ text: String, ts: UInt64) throws -> SignedMessage {
        guard mls.secrets != nil else { throw Failure.mlsNotReady }
        let sealed = try mls.seal(text)
        let signed = try append(kind: .control, payload: GroupPayload.encode(sealed), ts: ts)
        opened[signed.hash] = text
        return signed
    }

    /// A republish (§9.4) of a parent's message into this group, sealed
    /// like any payload.
    public func republish(_ republish: Republish, ts: UInt64) throws -> SignedMessage {
        guard mls.secrets != nil else { throw Failure.mlsNotReady }
        let sealed = try mls.seal("republish:" + republish.borsh.hex)
        let signed = try append(kind: .republish, payload: GroupPayload.encode(sealed), ts: ts)
        opened[signed.hash] = "republish:" + republish.borsh.hex
        republishes[signed.hash] = republish
        judge(signed.hash)
        return signed
    }

    /// §13.1 in-band host addition, a control message.
    public func addHost(_ node: PublicKey, ts: UInt64) throws -> SignedMessage {
        let signed = try control("host-add:" + node.hex, ts: ts)
        if !extraHosts.contains(node) { extraHosts.append(node) }
        return signed
    }

    /// §2: a self-Update commit advancing the MLS epoch, carried unsealed
    /// as a control message (it is what makes the next epoch's keys).
    public func rotateEpoch(ts: UInt64) throws -> SignedMessage {
        guard mls.secrets != nil else { throw Failure.mlsNotReady }
        let commit = try mls.createCommit(id: "\(mls.epoch + 1)-\(identity.publicKey.hex)", roster: roster.map(\.mlsMember))
        try mls.apply(commit, isOwn: true)
        let text = "mls-commit:" + GroupPayload.encode(commit).hex
        let signed = try append(kind: .control, payload: Array(text.utf8), ts: ts)
        opened[signed.hash] = text
        ownMessagesSinceUpdate = 0
        lastEpochUpdate = ts
        return signed
    }

    private func noteOwnActivity(at ts: UInt64) {
        ownMessagesSinceUpdate += 1
        if lastEpochUpdate == 0 { lastEpochUpdate = ts }
    }

    /// Whether `MLS_UPDATE_INTERVAL` of own activity has passed (§2): so
    /// many own messages, or so long since the epoch began with something
    /// of ours in it.
    public var epochUpdateDue: Bool { ownMessagesSinceUpdate >= Parameters.Client.mlsUpdateIntervalMessages }
    public func epochUpdateDue(at ts: UInt64) -> Bool {
        if epochUpdateDue { return true }
        guard ownMessagesSinceUpdate > 0, lastEpochUpdate > 0 else { return false }
        return ts >= lastEpochUpdate + UInt64(Parameters.Client.mlsUpdateIntervalSeconds * 1000)
    }

    private func append(kind: Message.Kind, payload: [UInt8], ts: UInt64) throws -> SignedMessage {
        let heads = dag.heads
        let parents = heads.isEmpty ? [groupID] : Array(heads.sorted().prefix(Int(genesis.maxParents)))
        let message = Message(groupID: groupID, authorIdx: memberIdx, seq: nextSeq, parents: parents, ts: ts, kind: kind, payload: payload)
        let signed = SignedMessage(message: message, signature: groupKey.sign(message.hash))
        try dag.insert(signed)
        nextSeq += 1
        return signed
    }

    // MARK: receiving

    /// Folds a peer's or a node's message in, verifying it against the
    /// genesis (§4), then opens it. Returns false for one already held.
    @discardableResult
    public func receive(_ signed: SignedMessage) throws -> Bool {
        do { try dag.insert(signed) } catch DAG.InsertError.duplicate { return false }
        let m = signed.message
        if m.authorIdx == memberIdx { nextSeq = max(nextSeq, m.seq + 1) }
        open(signed)
        if !pendingAttestations.isEmpty { drainPendingAttestations() }
        return true
    }

    private func open(_ signed: SignedMessage) {
        let m = signed.message
        if m.kind == Message.Kind.control.rawValue, let text = String(bytes: m.payload, encoding: .utf8), text.hasPrefix("mls-commit:") {
            // An Update commit travels unsealed; applying it advances the
            // epoch. One from our own index is another device of ours (the
            // one we made is already applied and comes back superseded).
            if let bytes = [UInt8](hex: String(text.dropFirst("mls-commit:".count))),
               let commit = try? GroupPayload.decodeCommit(bytes) { _ = try? mls.apply(commit) }
            opened[signed.hash] = text
            return
        }
        guard let sealed = try? GroupPayload.decodeSealed(m.payload), let text = try? mls.open(sealed) else { return }
        // Our own leaf sealed this on another device: never seal at that
        // generation again.
        if m.authorIdx == memberIdx, sealed.epoch == mls.epoch { mls.noteOwnGeneration(past: sealed.generation) }
        switch Message.Kind(rawValue: m.kind) {
        case .chat:
            opened[signed.hash] = text
        case .reaction:
            opened[signed.hash] = text
            if text.hasPrefix("react:"), let bytes = [UInt8](hex: String(text.dropFirst("react:".count))), let r = try? Reaction.decode(bytes) {
                reactions[signed.hash] = r
            }
        case .attachment:
            opened[signed.hash] = text
            if text.hasPrefix("attach:"), let bytes = [UInt8](hex: String(text.dropFirst("attach:".count))), let a = try? Attachment.decode(bytes) {
                attachments[signed.hash] = a
            }
        case .control:
            if text.hasPrefix("host-add:"), let node = Hash32(hex: String(text.dropFirst("host-add:".count))), !extraHosts.contains(node) {
                extraHosts.append(node)
            }
            opened[signed.hash] = text
        case .republish:
            opened[signed.hash] = text
            if text.hasPrefix("republish:"), let bytes = [UInt8](hex: String(text.dropFirst("republish:".count))), let rp = try? Republish.decode(bytes) {
                republishes[signed.hash] = rp
                judge(signed.hash)
            } else {
                republishVerdicts[signed.hash] = false
            }
        default: break
        }
    }

    /// §9.4 verification. Failing any check, the entry stays an ordinary
    /// message from the republisher (verdict false), never history.
    private func judge(_ hash: Hash32) {
        guard let rp = republishes[hash] else { return }
        let ok = rp.verify(parentMembers: parentMembers) { ref in resolvedSources.contains(ref) || ref.resolves() }
        republishVerdicts[hash] = ok
        if ok, opened[hash]?.hasPrefix("republish:") == true {
            opened[hash] = "[republished message \(rp.signedOriginal.hash.hex.prefix(8))]"
        }
    }

    private func rejudge() { for hash in republishes.keys { judge(hash) } }

    /// What a child needs to verify republishes from its parent (§9.4).
    public func setParent(members: [PublicKey]) {
        parentMembers = members
        rejudge()
    }

    /// Opens what arrived before its epoch's secrets were known.
    public func reopen() {
        for (hash, signed) in dag.messages where opened[hash] == nil { open(signed) }
    }

    /// Records an attestation; one over a head not yet held (signed by a
    /// member) waits until the head arrives, and meanwhile marks this
    /// member syncing. False for one that is neither.
    @discardableResult
    public func receive(_ attestation: SignedAttestation) -> Bool {
        if dag.record(attestation) { return true }
        let a = attestation.attestation
        guard a.groupID == groupID, a.signerIdx != memberIdx, Int(a.signerIdx) < genesis.members.count,
              attestation.verify(signer: genesis.members[Int(a.signerIdx)]), !dag.contains(a.head) else { return false }
        pendingAttestations[a.head, default: [:]][a.signerIdx] = attestation
        return true
    }

    /// Attestations over heads not held yet (§9.2), by head then signer.
    private var pendingAttestations: [Hash32: [UInt8: SignedAttestation]] = [:]

    /// Heads other members attested that this member does not hold: while
    /// any exist the member is **syncing** (§9.2: may read and send, may
    /// not attest), asks for them, and after `RECOVERY_PATIENCE` without
    /// an answer forks.
    public var unheldAttestedHeads: [Hash32] { pendingAttestations.keys.filter { !dag.contains($0) }.sorted() }
    public var isSyncing: Bool { !unheldAttestedHeads.isEmpty }

    /// After a message lands: attestations that waited for it (or for a
    /// head under it) are recorded if they now verify.
    private func drainPendingAttestations() {
        for (head, bySigner) in pendingAttestations where dag.contains(head) {
            var left: [UInt8: SignedAttestation] = [:]
            for (idx, att) in bySigner where !dag.record(att) {
                // Held but not yet complete underneath: keep waiting only
                // while something under it is still missing.
                if dag.messageCount(under: head) < att.attestation.msgCount { left[idx] = att }
            }
            pendingAttestations[head] = left.isEmpty ? nil : left
        }
    }

    public func adoptHost(_ node: PublicKey) { if !extraHosts.contains(node) { extraHosts.append(node) } }

    public func recordReceipt(_ receipt: Receipt) {
        receipts[receipt.body.nodePk, default: [:]][receipt.body.itemHash] = receipt
    }

    public func receipt(node: PublicKey, item: Hash32) -> Receipt? { receipts[node]?[item] }

    // MARK: §5 attesting

    /// Signs the current head if it is valid and fully held (§5), unless
    /// this member already signed that head.
    public func attest(head h: Hash32? = nil) -> SignedAttestation? {
        // §9.2: a syncing member does not attest.
        if isSyncing { return nil }
        let target = h ?? head
        guard target != groupID, dag.validate(head: target) == nil else { return nil }
        if dag.attestations(for: target).contains(where: { $0.attestation.signerIdx == memberIdx }) { return nil }
        let root = dag.contentRoot(under: target)
        let attestation = Attestation(groupID: groupID, head: target, contentRoot: root, msgCount: dag.messageCount(under: target), signerIdx: memberIdx)
        let signed = SignedAttestation.sign(attestation, with: groupKey)
        dag.record(signed)
        lastAttestedHead = target
        lastAttestedCount = attestation.msgCount
        return signed
    }

    public func noteAttested(at now: UInt64) { lastAttestTime = now }

    /// The cadence rule (§5, Appendix B.2): attest after `ATTEST_MSGS` new
    /// messages or `ATTEST_INTERVAL` with anything new (`now` in unix ms).
    public func attestationDue(now: UInt64) -> Bool {
        let count = messageCount
        guard count > lastAttestedCount || (lastAttestedHead != nil && head != lastAttestedHead) else { return false }
        return count - lastAttestedCount >= UInt64(Parameters.Client.attestMessages) || now &- lastAttestTime >= Parameters.Client.attestIntervalMs
    }

    public var attestations: [SignedAttestation] { dag.allAttestations }
    public func attestations(for head: Hash32) -> [SignedAttestation] { dag.attestations(for: head) }

    /// A head is `attested` once ≥ quorum distinct members cover it.
    public func isAttested(_ hash: Hash32) -> Bool { dag.attestingSigners(of: hash).count >= Int(genesis.quorum) }

    // MARK: §6 commitment

    /// Records a resolved `CommitmentRef` for an item held here.
    public func markCommitted(_ ref: CommitmentRef) {
        guard commitments[ref.itemHash] == nil else { return }
        commitments[ref.itemHash] = ref
        dag.markCommitted(ref.itemHash)
    }

    public func isCommitted(_ hash: Hash32) -> Bool { dag.committed.contains(hash) }

    /// Every item this member holds a receipt for that no commitment has
    /// resolved for yet, with the receipts, oldest first.
    public func awaitingCommitment() -> [(item: Hash32, receipts: [Receipt])] {
        var byItem: [Hash32: [Receipt]] = [:]
        for (_, items) in receipts { for (item, r) in items where commitments[item] == nil { byItem[item, default: []].append(r) } }
        return byItem.map { ($0.key, $0.value) }.sorted { ($0.1.map(\.body.received).min() ?? 0) < ($1.1.map(\.body.received).min() ?? 0) }
    }

    /// Receipts whose batch should have been published by `now` (unix ms;
    /// `COMMIT_INTERVAL + COMMIT_GRACE` past receipt) with no commitment yet:
    /// the node is late, and if the batch was published without the item, F4.
    public func overdueReceipts(at now: UInt64) -> [Receipt] {
        awaitingCommitment().flatMap(\.receipts).filter { now > $0.body.received + Parameters.Node.commitIntervalMs + Parameters.Client.commitGraceMs }
    }

    /// Drops receipts of committed items once past their retention (unix ms).
    public func forgetReceipts(past now: UInt64) {
        for (node, items) in receipts {
            receipts[node] = items.filter { !(commitments[$0.key] != nil && $0.value.body.retainUntil < now) }
        }
    }

    // MARK: §9 forks

    /// The `ParentRef` a child cites for `head`: a committed attestation of
    /// this group over it, from whichever node committed one.
    public func parentRef(head h: Hash32? = nil) -> (ref: ParentRef, attestation: SignedAttestation)? {
        let target = h ?? head
        for att in dag.attestations(for: target) {
            if let ref = commitments[att.itemHash] { return (ParentRef(groupID: groupID, head: target, source: ref), att) }
        }
        return nil
    }

    /// The latest attested head this member holds a committed attestation
    /// for: the fork point for membership, rotation and host changes.
    public var latestCommittedAttestedHead: Hash32? {
        var best: (Hash32, UInt64)?
        for att in dag.allAttestations where commitments[att.itemHash] != nil {
            let n = att.attestation.msgCount
            if best == nil || n > best!.1 { best = (att.attestation.head, n) }
        }
        return best?.0
    }

    public func carrySignature(for child: Hash32) -> (UInt8, [UInt8]) {
        (memberIdx, groupKey.sign(ForkAuthorization.preimage(parent: groupID, child: child)))
    }

    /// §9.4: this member's own committed messages past the fork point,
    /// as republishes citing a committed attestation that covers them.
    public func republishes(after forkHead: Hash32) -> [Republish] {
        let base = forkHead == groupID ? [] : dag.ancestors(of: forkHead)
        var out: [Republish] = []
        // Each candidate attestation covers what is under its head.
        let sources = dag.allAttestations.compactMap { att in commitments[att.itemHash].map { (att, $0) } }
        for hash in dag.messages.keys.sorted() where !base.contains(hash) && dag.committed.contains(hash) {
            guard let signed = dag.messages[hash], signed.message.authorIdx == memberIdx, signed.message.kind == Message.Kind.chat.rawValue else { continue }
            guard let (att, ref) = sources.first(where: { $0.0.attestation.head == hash || dag.ancestors(of: $0.0.attestation.head).contains(hash) }),
                  let proof = dag.inclusionProof(of: hash, under: att.attestation.head) else { continue }
            out.append(Republish(parentGroupID: groupID, source: ref, attestation: att, original: signed, inclusionProof: proof))
        }
        return out
    }

    /// §9.6: this member's own chat messages never committed, to be sent
    /// again in a child.
    public func uncommittedOwnTexts() -> [String] {
        let h = head
        guard h != groupID else { return [] }
        return dag.canonicalOrder(under: h).compactMap { hash in
            guard !dag.committed.contains(hash), let m = dag.messages[hash]?.message, m.authorIdx == memberIdx,
                  m.kind == Message.Kind.chat.rawValue else { return nil }
            return opened[hash]
        }
    }

    // MARK: §12 sync

    public func syncRequest(wantHead: Hash32, missing: [Hash32]?, time: UInt64) -> SyncRequest {
        let have = head == groupID ? Hash32.zero : head
        let body = SyncRequest.Body(groupID: groupID, haveHead: have, wantHead: wantHead, missing: missing,
                                    nonce: (0..<16).map { _ in UInt8.random(in: 0...255) }, time: time, requesterIdx: memberIdx)
        return SyncRequest.sign(body, with: groupKey)
    }

    /// Runs `body` over an inout copy of the DAG (the sync client works on
    /// one), keeps the result and opens what arrived.
    public func withDAG<T>(_ body: (inout DAG) async throws -> T) async rethrows -> T {
        var copy = dag
        let result = try await body(&copy)
        dag = copy
        reopen()
        return result
    }

    public func replaceDAG(_ dag: DAG) { self.dag = dag; reopen() }

    /// The synchronous form, for hosts without concurrency.
    public func withDAGSync<T>(_ body: (inout DAG) throws -> T) rethrows -> T {
        var copy = dag
        let result = try body(&copy)
        dag = copy
        reopen()
        return result
    }
}
