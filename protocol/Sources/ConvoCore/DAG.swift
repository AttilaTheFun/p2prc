import ConvoFoundation

/// §4: the message DAG of one group, with the attestations members have
/// signed over its heads (§5) and which items the client knows to be
/// committed (§6). Validity rules are checked on insert; canonical order
/// and `content_root` are computed under any head.
public struct DAG: Sendable {
    public let genesis: Genesis
    public let groupID: Hash32
    public private(set) var messages: [Hash32: SignedMessage] = [:]
    private var children: [Hash32: Set<Hash32>] = [:]
    /// Verified attestations by head, then signer.
    private var attestations: [Hash32: [UInt8: SignedAttestation]] = [:]
    /// Items a `CommitmentRef` has resolved for (§6).
    public private(set) var committed: Set<Hash32> = []

    public init(genesis: Genesis) {
        self.genesis = genesis
        self.groupID = genesis.groupID
    }

    /// A DAG for a party that never saw the genesis but knows the group's
    /// id and members: signatures and authorship are still checked; the
    /// genesis limits are not.
    public init(groupID: Hash32, members: [PublicKey]) {
        self.genesis = Genesis(salt: groupID, members: members, quorum: UInt8(clamping: members.count),
                               maxParents: .max, maxPayload: .max, maxUncommittedRepublish: .max, homeNodes: [])
        self.groupID = groupID
    }

    public enum InsertError: Error, Equatable {
        case wrongGroup, badSignature, badAuthor, badParentCount, unknownParent(Hash32), payloadTooLarge, duplicate, badVersion
    }

    /// Inserts a message after checking everything that can be checked
    /// locally (§4 rules except the republish cap, which is per head).
    /// Parents must already be present (or be the group id).
    @discardableResult
    public mutating func insert(_ signed: SignedMessage) throws -> Hash32 {
        let m = signed.message
        guard m.version == Message.currentVersion else { throw InsertError.badVersion }
        guard m.groupID == groupID else { throw InsertError.wrongGroup }
        guard Int(m.authorIdx) < genesis.members.count else { throw InsertError.badAuthor }
        guard signed.verify(author: genesis.members[Int(m.authorIdx)]) else { throw InsertError.badSignature }
        guard !m.parents.isEmpty, m.parents.count <= Int(genesis.maxParents) else { throw InsertError.badParentCount }
        // In 64 bits: on wasm32 `Int` can't hold UInt32.max (an unlimited genesis).
        guard UInt64(m.payload.count) <= UInt64(genesis.maxPayload) else { throw InsertError.payloadTooLarge }
        if messages[signed.hash] != nil { throw InsertError.duplicate }
        for p in m.parents where p != groupID && messages[p] == nil { throw InsertError.unknownParent(p) }
        messages[signed.hash] = signed
        for p in m.parents { children[p, default: []].insert(signed.hash) }
        return signed.hash
    }

    public func contains(_ hash: Hash32) -> Bool { messages[hash] != nil }

    /// Messages with no known children.
    public var heads: [Hash32] {
        messages.keys.filter { (children[$0] ?? []).isEmpty }.sorted()
    }

    /// Every message under `head` (inclusive), as a set.
    public func ancestors(of head: Hash32) -> Set<Hash32> {
        var seen: Set<Hash32> = []
        var stack = [head]
        while let h = stack.popLast() {
            guard h != groupID, !seen.contains(h), let m = messages[h] else { continue }
            seen.insert(h)
            stack.append(contentsOf: m.message.parents)
        }
        return seen
    }

    /// §4 canonical order under `head`: Kahn's topological sort, ties by
    /// smallest `msg_hash` first. `ts` never matters.
    public func canonicalOrder(under head: Hash32) -> [Hash32] { canonicalOrder(under: [head]) }

    /// The same order over everything under any of `heads`: concurrent
    /// branches side by side, as a reader sees them before the next
    /// message joins them.
    public func canonicalOrder(under heads: [Hash32]) -> [Hash32] {
        var set: Set<Hash32> = []
        for head in heads { set.formUnion(ancestors(of: head)) }
        var indegree: [Hash32: Int] = [:]
        var kids: [Hash32: [Hash32]] = [:]
        for h in set {
            let parents = messages[h]!.message.parents.filter { set.contains($0) }
            indegree[h] = parents.count
            for p in parents { kids[p, default: []].append(h) }
        }
        var ready = set.filter { indegree[$0] == 0 }.sorted()
        var order: [Hash32] = []
        order.reserveCapacity(set.count)
        while !ready.isEmpty {
            let next = ready.removeFirst()
            order.append(next)
            for k in (kids[next] ?? []).sorted() {
                indegree[k]! -= 1
                if indegree[k] == 0 {
                    let at = ready.firstIndex { k < $0 } ?? ready.count
                    ready.insert(k, at: at)
                }
            }
        }
        return order
    }

    public func leaves(under head: Hash32) -> [Hash32] {
        canonicalOrder(under: head).map { messages[$0]!.leaf }
    }

    /// §4 `content_root(head)`.
    public func contentRoot(under head: Hash32) -> Hash32 {
        Merkle.root(leaves: leaves(under: head))
    }

    /// The inclusion proof of a message under `head`.
    public func inclusionProof(of hash: Hash32, under head: Hash32) -> [Merkle.ProofStep]? {
        let order = canonicalOrder(under: head)
        guard let index = order.firstIndex(of: hash) else { return nil }
        return Merkle.proof(leaves: order.map { messages[$0]!.leaf }, index: index)
    }

    public func messageCount(under head: Hash32) -> UInt64 { UInt64(ancestors(of: head).count) }

    // MARK: - Validity (§4)

    public enum Invalidity: Error, Equatable {
        case unknownHead
        case republishCapExceeded(authorIdx: UInt8, count: Int)
    }

    /// A head is valid only if every message under it satisfies §4. The
    /// per-message rules were checked at insert; what remains is the
    /// republish cap over the uncommitted range.
    public func validate(head: Hash32) -> Invalidity? {
        guard messages[head] != nil else { return .unknownHead }
        var republishes: [UInt8: Int] = [:]
        for h in ancestors(of: head) where !committed.contains(h) {
            let m = messages[h]!.message
            if m.kind == Message.Kind.republish.rawValue { republishes[m.authorIdx, default: 0] += 1 }
        }
        for (author, count) in republishes where count > Int(genesis.maxUncommittedRepublish) {
            return .republishCapExceeded(authorIdx: author, count: count)
        }
        return nil
    }

    // MARK: - Attestations (§5)

    /// Records an attestation after verifying its signature and that its
    /// content root and count match the messages held under the head.
    @discardableResult
    public mutating func record(_ signed: SignedAttestation) -> Bool {
        let a = signed.attestation
        guard a.groupID == groupID, Int(a.signerIdx) < genesis.members.count,
              signed.verify(signer: genesis.members[Int(a.signerIdx)]),
              messages[a.head] != nil,
              a.contentRoot == contentRoot(under: a.head), a.msgCount == messageCount(under: a.head) else { return false }
        attestations[a.head, default: [:]][a.signerIdx] = signed
        return true
    }

    public func attestations(for head: Hash32) -> [SignedAttestation] {
        (attestations[head] ?? [:]).values.sorted { $0.attestation.signerIdx < $1.attestation.signerIdx }
    }

    public var allAttestations: [SignedAttestation] {
        attestations.values.flatMap { $0.values }.sorted { ($0.attestation.head, $0.attestation.signerIdx) < ($1.attestation.head, $1.attestation.signerIdx) }
    }

    /// Distinct signers that attested this head or any descendant (§5: a
    /// signature on a head transitively attests every ancestor).
    public func attestingSigners(of hash: Hash32) -> Set<UInt8> {
        var signers: Set<UInt8> = []
        for (head, bySigner) in attestations where head == hash || ancestors(of: head).contains(hash) {
            signers.formUnion(bySigner.keys)
        }
        return signers
    }

    // MARK: - Commitment (§6)

    /// Marks an item (message or attestation hash) committed.
    public mutating func markCommitted(_ hash: Hash32) { committed.insert(hash) }

    public func state(of hash: Hash32) -> MessageState {
        if committed.contains(hash) { return .committed }
        if attestingSigners(of: hash).count >= Int(genesis.quorum) { return .attested }
        return .sent
    }

    /// Messages under `head` not yet committed, in canonical order.
    public func uncommitted(under head: Hash32) -> [Hash32] {
        canonicalOrder(under: head).filter { !committed.contains($0) }
    }
}

/// §6 message states, as the client shows them.
public enum MessageState: String, Sendable, Codable {
    /// Author-signed, receipted by ≥ 1 home node.
    case sent
    /// A `CommitmentRef` resolves for it.
    case committed
    /// Under a head with ≥ `quorum` attestations.
    case attested
    /// Committed in a group that was forked away from, past the fork point.
    case abandoned
}
