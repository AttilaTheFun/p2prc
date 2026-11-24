import ConvoCore
import ConvoMLS
import ConvoNet
import ConvoSession
import Foundation

/// `GroupState` behind an actor, for clients that run with Swift
/// concurrency (the reference client, the demo). Every member forwards.
public actor GroupSession {
    public typealias Entry = GroupState.Entry

    private let state: GroupState
    nonisolated public let genesis: Genesis
    nonisolated public let groupID: Hash32
    nonisolated public let identity: ConvoIdentity
    nonisolated public let groupKey: SigningKey
    nonisolated public let memberIdx: UInt8
    nonisolated public let roster: [KeyPackage]

    public init(_ state: sending GroupState) {
        self.state = state
        genesis = state.genesis; groupID = state.groupID; identity = state.identity
        groupKey = state.groupKey; memberIdx = state.memberIdx; roster = state.roster
    }

    public init(genesis: Genesis, roster: [KeyPackage], identity: ConvoIdentity, commitSecret: [UInt8], ownGeneration: UInt32, epoch: UInt64 = 1,
                updatedAt: UInt64 = 0) throws {
        self.init(try GroupState(genesis: genesis, roster: roster, identity: identity, commitSecret: commitSecret, ownGeneration: ownGeneration, epoch: epoch,
                                 updatedAt: updatedAt))
    }

    public var dag: DAG { state.dag }
    public var receipts: [PublicKey: [Hash32: Receipt]] { state.receipts }
    public var commitments: [Hash32: CommitmentRef] { state.commitments }
    public var extraHosts: [PublicKey] { state.extraHosts }
    public var parentMembers: [PublicKey] { state.parentMembers }
    public var mlsState: (commitSecret: [UInt8], ownGeneration: UInt32, epoch: UInt64, updatedAt: UInt64)? { state.mlsState }
    public var hosts: [PublicKey] { state.hosts }
    public var identities: [PublicKey] { state.identities }
    public var head: Hash32 { state.head }
    public var heads: [Hash32] { state.heads }
    public var ready: Bool { state.ready }
    public var messageCount: UInt64 { state.messageCount }
    public var attestations: [SignedAttestation] { state.attestations }
    public func epochUpdateDue(at ts: UInt64) -> Bool { state.epochUpdateDue(at: ts) }
    public var lastEpochUpdate: UInt64 { state.lastEpochUpdate }
    public var unheldAttestedHeads: [Hash32] { state.unheldAttestedHeads }
    public var isSyncing: Bool { state.isSyncing }
    public var epochUpdateDue: Bool { state.epochUpdateDue }
    public var latestCommittedAttestedHead: Hash32? { state.latestCommittedAttestedHead }

    public func entries() -> [Entry] { state.entries() }
    public func message(_ hash: Hash32) -> SignedMessage? { state.message(hash) }
    public func contains(_ hash: Hash32) -> Bool { state.contains(hash) }
    public func state(of hash: Hash32) -> MessageState { state.state(of: hash) }
    public func republish(_ hash: Hash32) -> Republish? { state.republish(hash) }
    public func send(_ text: String, ts: UInt64) throws -> SignedMessage { try state.send(text, ts: ts) }
    public func control(_ text: String, ts: UInt64) throws -> SignedMessage { try state.control(text, ts: ts) }
    public func sendReaction(to target: Hash32, emoji: String, remove: Bool = false, ts: UInt64) throws -> SignedMessage {
        try state.sendReaction(to: target, emoji: emoji, remove: remove, ts: ts)
    }
    public func sendAttachment(_ attachment: Attachment, ts: UInt64) throws -> SignedMessage { try state.sendAttachment(attachment, ts: ts) }
    public func reactions(on target: Hash32) -> [(emoji: String, authors: [UInt8])] { state.reactions(on: target) }
    public var attachments: [Hash32: Attachment] { state.attachments }
    public func republish(_ republish: Republish, ts: UInt64) throws -> SignedMessage { try state.republish(republish, ts: ts) }
    public func addHost(_ node: PublicKey, ts: UInt64) throws -> SignedMessage { try state.addHost(node, ts: ts) }
    public func rotateEpoch(ts: UInt64) throws -> SignedMessage { try state.rotateEpoch(ts: ts) }
    @discardableResult public func receive(_ signed: SignedMessage) throws -> Bool { try state.receive(signed) }
    @discardableResult public func receive(_ attestation: SignedAttestation) -> Bool { state.receive(attestation) }
    public func setParent(members: [PublicKey]) { state.setParent(members: members) }
    public func markResolved(_ ref: CommitmentRef) { state.markResolved(ref) }
    public var resolvedSources: Set<CommitmentRef> { state.resolvedSources }
    public var unresolvedSources: [CommitmentRef] { state.unresolvedSources }
    public func reopen() { state.reopen() }
    public func adoptHost(_ node: PublicKey) { state.adoptHost(node) }
    public func recordReceipt(_ receipt: Receipt) { state.recordReceipt(receipt) }
    public func receipt(node: PublicKey, item: Hash32) -> Receipt? { state.receipt(node: node, item: item) }
    public func attest(head h: Hash32? = nil) -> SignedAttestation? { state.attest(head: h) }
    public func noteAttested(at now: UInt64) { state.noteAttested(at: now) }
    public func attestationDue(now: UInt64) -> Bool { state.attestationDue(now: now) }
    public func attestations(for head: Hash32) -> [SignedAttestation] { state.attestations(for: head) }
    public func isAttested(_ hash: Hash32) -> Bool { state.isAttested(hash) }
    public func markCommitted(_ ref: CommitmentRef) { state.markCommitted(ref) }
    public func isCommitted(_ hash: Hash32) -> Bool { state.isCommitted(hash) }
    public func awaitingCommitment() -> [(item: Hash32, receipts: [Receipt])] { state.awaitingCommitment() }
    public func overdueReceipts(at now: UInt64) -> [Receipt] { state.overdueReceipts(at: now) }
    public func parentRef(head h: Hash32? = nil) -> (ref: ParentRef, attestation: SignedAttestation)? { state.parentRef(head: h) }
    public func carrySignature(for child: Hash32) -> (UInt8, [UInt8]) { state.carrySignature(for: child) }
    public func republishes(after forkHead: Hash32) -> [Republish] { state.republishes(after: forkHead) }
    public func uncommittedOwnTexts() -> [String] { state.uncommittedOwnTexts() }
    public func syncRequest(wantHead: Hash32, missing: [Hash32]?, time: UInt64) -> SyncRequest { state.syncRequest(wantHead: wantHead, missing: missing, time: time) }

    /// Runs `body` over an inout copy of the DAG (the sync client works on
    /// one), keeps the result and opens what arrived.
    public func withDAG<T: Sendable>(_ body: @Sendable (inout DAG) async throws -> T) async rethrows -> T {
        var copy = state.dag
        let result = try await body(&copy)
        state.replaceDAG(copy)
        return result
    }
}
