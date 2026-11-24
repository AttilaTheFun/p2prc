import ConvoCore
import ConvoSession
import ConvoMLS
import ConvoNet
import Crypto
import Foundation

/// The client loop: one identity, its groups, and its opinion of nodes.
/// Everything a UI needs is returned as data (`GroupSession.Entry`,
/// health, states); nothing here renders. Commitments are read from home
/// nodes and verified against the witnessed checkpoints they carry (§6,
/// §11); fraud proofs are kept and gossiped to the nodes it knows (§17).
public actor ConvoClient {
    nonisolated public let identity: ConvoIdentity
    nonisolated public let name: String
    nonisolated public let store: ClientStore?
    nonisolated public let directory: NodeDirectory
    public private(set) var groups: [Hash32: GroupSession] = [:]
    public private(set) var health = NodeHealth()
    public var bounds = HostPolicy.Bounds()
    public var log: (@Sendable (String) -> Void)?
    /// Fraud proofs this client has built (and submitted, where it could).
    public private(set) var fraudProofs: [FraudProof] = []
    private var responsesByRequest: [Hash32: FetchResponse] = [:]
    private var hostChangeSince: [Hash32: Date] = [:]
    /// Handshakes in flight, by salt. The creator's and joiner's state
    /// machines are not Sendable, so they live here.
    private var creations: [Hash32: HandshakeCreator] = [:]
    private var joins: [Hash32: HandshakeJoiner] = [:]
    /// The newest checkpoint seen of each node's log, from the refs and
    /// checkpoints it served: two that disagree are F6 (§11, §17).
    private var checkpoints: [PublicKey: Checkpoint] = [:]
    /// The newest identity record known per identity (§13.2).
    public private(set) var identityRecords: [PublicKey: IdentityRecord] = [:]
    /// Cosignatures a ref's checkpoint needs (§6); a client may ask for more.
    public var witnessQuorum = Parameters.Client.witnessQuorum
    public var now: @Sendable () -> Date = { Date() }

    public enum Failure: Error, Equatable {
        case unknownGroup, noHosts, noReceipt, noKeyPackage, notCommitted, handshakeIncomplete, notReady, badParent, noResponse
    }

    public init(identity: ConvoIdentity, name: String, store: ClientStore? = nil, directory: NodeDirectory = NodeDirectory()) {
        self.identity = identity
        self.name = name
        self.store = store
        self.directory = directory
        store?.saveIdentity(identity)
        store?.name = name
    }

    /// Restores groups from the store.
    public func load() async {
        guard let store else { return }
        for id in store.groupIDs where groups[id] == nil {
            if let session = await store.loadGroup(id, identity: identity) { groups[id] = session }
        }
        for (_, s) in groups { await linkParent(s) }
        fraudProofs = store.fraudProofs
    }

    /// A child verifies republishes against its parent (§9.4); the parent
    /// session, when held, supplies its members.
    private func linkParent(_ s: GroupSession) async {
        guard let ref = s.genesis.parent, let parent = groups[ref.groupID] else { return }
        await s.setParent(members: parent.genesis.members)
    }

    public func session(_ groupID: Hash32) throws -> GroupSession {
        guard let s = groups[groupID] else { throw Failure.unknownGroup }
        return s
    }

    public func adopt(_ session: GroupSession) async {
        groups[session.groupID] = session
        await linkParent(session)
        await store?.saveGroup(session)
    }

    /// An observation from outside the client loop (the app's own
    /// signaling or ICE attempt against a node), folded into health.
    public func recordHealth(_ node: PublicKey, success: Bool, at date: Date? = nil) {
        health.record(node, success: success, at: date ?? now())
    }

    /// Unix ms on this device's clock.
    private func ts() -> UInt64 { UInt64(max(0, now().timeIntervalSince1970 * 1000)) }

    // MARK: directory and rendezvous (§13.1, §24)

    /// The nodes this client knows, less those proven faulty.
    public func knownNodes() async -> [PublicKey] {
        await directory.known.filter { health.score($0, at: now()) > -.infinity }
    }

    /// `RV(key, k_rv)` over the client's directory, restricted to nodes it
    /// can reach; the reachable known nodes stand in when none of the set is.
    public func rendezvousNodes(for key: Hash32) async -> [PublicKey] {
        let known = await knownNodes()
        let set = HostPolicy.rendezvous(key: key, directory: known, health: health, at: now())
        var reachable: [PublicKey] = []
        for n in set where await directory.client(n) != nil { reachable.append(n) }
        if reachable.isEmpty {
            for n in known where await directory.client(n) != nil { reachable.append(n) }
            reachable = Array(reachable.prefix(Parameters.Client.rendezvousSetSize))
        }
        return reachable
    }

    // MARK: identity records (§13.2)

    /// Keeps a valid record newer than the one held.
    public func learn(_ record: IdentityRecord) {
        guard record.isValid, identityRecords[record.idPk].map({ record.updated > $0.updated }) ?? true else { return }
        identityRecords[record.idPk] = record
    }

    /// Signs this identity's record naming `nodes` (by default its
    /// rendezvous set) and publishes it to them and to `RV(id_pk)`.
    @discardableResult
    public func publishIdentity(nodes: [PublicKey]? = nil) async throws -> IdentityRecord {
        var chosen = nodes ?? []
        if nodes == nil { chosen = await rendezvousNodes(for: identity.publicKey) }
        var refs: [NodeRef] = []
        for n in chosen.prefix(IdentityRecord.maxNodes) { refs.append(NodeRef(nodePk: n, url: await directory.url(n) ?? "")) }
        guard !refs.isEmpty else { throw Failure.noHosts }
        let record = IdentityRecord.sign(nodes: refs, updated: ts(), with: identity.key)
        learn(record)
        var targets = refs.map(\.nodePk)
        for n in await rendezvousNodes(for: identity.publicKey) where !targets.contains(n) { targets.append(n) }
        var published = 0
        for n in targets {
            guard let client = await directory.client(n) else { continue }
            if (try? await client.publishIdentity(record)) != nil { published += 1 }
        }
        guard published > 0 else { throw Failure.noReceipt }
        return record
    }

    /// The nodes that hold an identity's KeyPackages and receive its
    /// invitations: its record's (learned from `RV(id_pk)` when unknown),
    /// else `RV(id_pk)` itself.
    public func identityNodes(for id: PublicKey) async -> [PublicKey] {
        let rv = await rendezvousNodes(for: id)
        if identityRecords[id] == nil {
            for n in rv {
                if let client = await directory.client(n), let record = try? await client.identity(id) { learn(record) }
            }
        }
        var nodes: [PublicKey] = []
        for ref in identityRecords[id]?.nodes ?? [] {
            if await directory.client(ref.nodePk) == nil, !ref.url.isEmpty { _ = try? await directory.add(url: ref.url) }
            if await directory.client(ref.nodePk) != nil { nodes.append(ref.nodePk) }
        }
        for n in rv where !nodes.contains(n) { nodes.append(n) }
        return nodes
    }

    // MARK: KeyPackages

    public var keyPackage: KeyPackage { identity.keyPackage(name: name) }

    /// Publishes this identity's KeyPackage to the nodes of its identity
    /// record and `RV(id_pk, k_rv)` (§13.2).
    public func publishKeyPackage() async throws {
        let targets = await identityNodes(for: identity.publicKey)
        guard !targets.isEmpty else { throw Failure.noHosts }
        for n in targets {
            guard let client = await directory.client(n) else { continue }
            do { _ = try await client.publishKeyPackage(identity: identity.publicKey, bytes: keyPackage.wire); health.record(n, success: true, at: now()) }
            catch { health.record(n, success: false, at: now()) }
        }
    }

    public func fetchKeyPackage(_ id: PublicKey) async throws -> KeyPackage {
        if id == identity.publicKey { return keyPackage }
        for n in await identityNodes(for: id) {
            guard let client = await directory.client(n) else { continue }
            if let bytes = try? await client.keyPackage(identity: id), let kp = try? KeyPackage.fromWire(bytes), kp.body.identityPk == id, !kp.isExpired(at: now()) { return kp }
        }
        throw Failure.noKeyPackage
    }

    // MARK: handshake transport (Part III: rendezvous boxes)

    public func dropHandshake(_ frame: [UInt8], salt: Hash32, to recipient: PublicKey) async {
        let box = NodeAPI.handshakeBox(salt: salt, recipient: recipient)
        for n in await rendezvousNodes(for: recipient) {
            if let client = await directory.client(n) { try? await client.drop(frame, box: box) }
        }
    }

    public func pollHandshake(salt: Hash32) async -> [[UInt8]] {
        let box = NodeAPI.handshakeBox(salt: salt, recipient: identity.publicKey)
        var frames: [[UInt8]] = []
        for n in await rendezvousNodes(for: identity.publicKey) {
            guard let client = await directory.client(n) else { continue }
            while let frame = try? await client.poll(box: box) { frames.append(frame) }
        }
        return frames
    }

    // MARK: creating and joining groups (§2)

    public func setBounds(minHealthy: Int? = nil, minTotal: Int? = nil, maxTotal: Int? = nil) {
        if let minHealthy { bounds.minHealthy = minHealthy }
        if let minTotal { bounds.minTotal = minTotal }
        if let maxTotal { bounds.maxTotal = maxTotal }
    }

    /// Creates a group with `members` (identity keys; this identity is
    /// added if missing), running the handshake over rendezvous boxes:
    /// invites go out, then `completeCreation` collects the announces.
    /// A fork cites `parent` at `forkHead` (or its latest committed
    /// attested head), which needs a committed attestation on it.
    public func beginCreation(members: [PublicKey], homeNodes: [PublicKey]? = nil, parent: GroupSession? = nil, forkHead: Hash32? = nil,
                              reason: Genesis.Reason = .root, salt: Hash32? = nil) async throws -> Hash32 {
        var roster: [KeyPackage] = [keyPackage]
        for id in members where id != identity.publicKey { roster.append(try await fetchKeyPackage(id)) }
        let hosts: [PublicKey]
        if let homeNodes { hosts = homeNodes }
        else {
            let known = await knownNodes()
            var current: [PublicKey] = []
            if let parent { current = await parent.hosts }
            hosts = HostPolicy.replacementHosts(current: current, groupID: parent?.groupID ?? Hash32(identity.publicKey.bytes),
                                                directory: known, health: health, bounds: bounds, at: now())
        }
        guard (bounds.minTotal...bounds.maxTotal).contains(hosts.count) else { throw Failure.noHosts }
        var ref: ParentRef?
        var cited: SignedAttestation?
        if let parent {
            var head = forkHead
            if head == nil { head = await parent.latestCommittedAttestedHead }
            guard let head, let (r, a) = await parent.parentRef(head: head) else { throw Failure.notCommitted }
            ref = r; cited = a
        }
        let proposal = HandshakeFrame.Proposal.defaults(members: roster.count, homeNodes: hosts, parent: ref, parentAttestation: cited, reason: reason)
        let creator = try salt.map { try HandshakeCreator(identity: identity, roster: roster, proposal: proposal, salt: $0) }
            ?? HandshakeCreator(identity: identity, roster: roster, proposal: proposal)
        if let parent {
            creator.parentMembers = parent.genesis.members
            creator.parentIdentities = await parent.identities
        }
        creations[creator.salt] = creator
        store?.saveHandshake(salt: creator.salt, role: "creator", bytes: creator.snapshot)
        let invite = creator.invite()
        for k in roster.dropFirst() { await dropHandshake(invite, salt: creator.salt, to: k.body.identityPk) }
        return creator.salt
    }

    private func creation(_ salt: Hash32) throws -> HandshakeCreator {
        if let c = creations[salt] { return c }
        if let bytes = store?.loadHandshake(salt: salt, role: "creator"), let c = try? HandshakeCreator(snapshot: bytes, identity: identity) {
            creations[salt] = c
            return c
        }
        throw Failure.unknownGroup
    }

    private func joiner(_ salt: Hash32) -> HandshakeJoiner {
        if let j = joins[salt] { return j }
        let j = (store?.loadHandshake(salt: salt, role: "joiner")).flatMap { try? HandshakeJoiner(snapshot: $0, identity: identity) } ?? HandshakeJoiner(identity: identity)
        joins[salt] = j
        return j
    }

    public func creationState(_ salt: Hash32) -> (complete: Bool, genesis: Genesis?, carries: Int)? {
        creations[salt].map { ($0.isComplete, $0.genesis, $0.carrySigs.count) }
    }

    /// Polls announces (and carries); once every member has announced,
    /// sends the genesis, adopts the session, and hands the genesis bytes
    /// to the home nodes (§13). The group's only public trace is the
    /// commitments of its items. Returns the session when complete.
    public func completeCreation(_ salt: Hash32, parent: GroupSession? = nil) async throws -> GroupSession? {
        let creator = try creation(salt)
        for frame in await pollHandshake(salt: creator.salt) {
            if let genesisFrame = try creator.receive(frame) {
                for k in creator.roster.dropFirst() { await dropHandshake(genesisFrame, salt: creator.salt, to: k.body.identityPk) }
            }
        }
        store?.saveHandshake(salt: salt, role: "creator", bytes: creator.snapshot)
        guard let g = creator.genesis else { return nil }
        if let existing = groups[g.groupID] {
            try await publishGenesis(existing, carrySigs: creator.carrySigs)
            return existing
        }
        let session = GroupSession(try creator.session())
        let parent = parent ?? session.genesis.parent.flatMap { groups[$0.groupID] }
        if let parent {
            let (idx, sig) = await parent.carrySignature(for: session.groupID)
            _ = try? creator.receive({ var w = BorshWriter(); w.u8(HandshakeFrame.carry); w.u8(idx); w.fixed(sig); return w.bytes }())
            await session.setParent(members: parent.genesis.members)
        }
        await adopt(session)
        try await publishGenesis(session, carrySigs: creator.carrySigs)
        return session
    }

    /// `POST /v1/groups/<id>/genesis` at every home node (§13).
    public func publishGenesis(_ session: GroupSession, carrySigs: [(UInt8, [UInt8])]) async throws {
        let record = GenesisRecord(genesis: session.genesis, carrySigs: carrySigs)
        var ok = 0
        for node in session.genesis.homeNodes {
            guard let client = await directory.client(node) else { continue }
            do { try await client.publishGenesis(record); ok += 1 } catch { log?("genesis not taken by \(node.hex.prefix(8)): \(error)") }
        }
        if ok == 0 { throw Failure.noHosts }
    }

    /// Carries that arrived after creation are gossiped to the home nodes.
    public func submitLateCarries(_ salt: Hash32) async throws {
        guard let creator = try? creation(salt), let g = creator.genesis, let session = groups[g.groupID] else { return }
        for frame in await pollHandshake(salt: creator.salt) { _ = try? creator.receive(frame) }
        store?.saveHandshake(salt: salt, role: "creator", bytes: creator.snapshot)
        try await publishGenesis(session, carrySigs: creator.carrySigs)
    }

    /// Joins invitations waiting in this identity's boxes for `salt`.
    /// Returns the session once the genesis frame has arrived.
    public func join(salt: Hash32, parent: GroupSession? = nil) async throws -> GroupSession? {
        let joiner = joiner(salt)
        joiner.minTotalHosts = bounds.minTotal
        joiner.maxTotalHosts = bounds.maxTotal
        if let parent { joiner.parentMembers = parent.genesis.members }
        for frame in await pollHandshake(salt: salt) {
            if let reply = try joiner.receive(frame), let s = joiner.salt {
                if let creator = joiner.roster.first { await dropHandshake(reply, salt: s, to: creator.body.identityPk) }
            }
        }
        store?.saveHandshake(salt: salt, role: "joiner", bytes: joiner.snapshot)
        guard let g = joiner.genesis else { return nil }
        if let existing = groups[g.groupID] { return existing }
        // §9.3: a parent ref must resolve against its witnessed checkpoint.
        if let ref = g.parent, !resolves(ref.source) { throw Failure.badParent }
        let session = GroupSession(try joiner.session())
        let parent = parent ?? g.parent.flatMap { groups[$0.groupID] }
        if let parent, g.parent?.groupID == parent.groupID, let creator = joiner.roster.first {
            let carry = try joiner.carry(parentIdx: parent.memberIdx, parentKey: parent.groupKey)
            await dropHandshake(carry, salt: g.salt, to: creator.body.identityPk)
            await session.setParent(members: parent.genesis.members)
        }
        await adopt(session)
        return session
    }

    // MARK: sending (§10, §14)

    @discardableResult
    public func send(_ text: String, in groupID: Hash32) async throws -> SignedMessage {
        let s = try session(groupID)
        let signed = try await s.send(text, ts: ts())
        try await publish(signed.wire, kind: .message, itemHash: signed.hash, session: s)
        if await s.epochUpdateDue(at: ts()) {
            let update = try await s.rotateEpoch(ts: ts())
            try? await publish(update.wire, kind: .message, itemHash: update.hash, session: s)
        }
        await store?.saveGroup(s)
        return signed
    }

    /// A self-Update commit now (§2), published to the hosts.
    @discardableResult
    public func rotateEpoch(in groupID: Hash32) async throws -> SignedMessage {
        let s = try session(groupID)
        let update = try await s.rotateEpoch(ts: ts())
        try await publish(update.wire, kind: .message, itemHash: update.hash, session: s)
        await store?.saveGroup(s)
        return update
    }

    /// Kind 3: a reaction on `target`; `remove` takes this member's earlier
    /// one with the same emoji back.
    public func react(to target: Hash32, emoji: String, remove: Bool = false, in groupID: Hash32) async throws -> SignedMessage {
        let s = try session(groupID)
        let signed = try await s.sendReaction(to: target, emoji: emoji, remove: remove, ts: ts())
        try await publish(signed.wire, kind: .message, itemHash: signed.hash, session: s)
        await store?.saveGroup(s)
        return signed
    }

    /// Kind 4: seals `plaintext` under a fresh key, puts the blob at every
    /// healthy host, and sends the attachment naming it.
    public func sendAttachment(_ plaintext: [UInt8], mime: String, width: UInt32, height: UInt32, caption: String = "",
                               in groupID: Hash32) async throws -> SignedMessage {
        let s = try session(groupID)
        let (key, sealed) = try BlobSeal.seal(plaintext)
        var hosts = HostPolicy.writeSet(await s.hosts, health: health, at: now())
        if hosts.isEmpty { hosts = await rendezvousNodes(for: groupID) }
        var stored = 0
        for n in hosts {
            guard let client = await directory.client(n) else { continue }
            if (try? await client.sendBlob(sealed, groupID: groupID, expectedNode: n)) != nil { stored += 1 }
        }
        guard stored > 0 else { throw Failure.noHosts }
        let attachment = Attachment(blob: BlobSeal.name(of: sealed), key: key, mime: mime, width: width, height: height,
                                    size: UInt64(sealed.count), caption: caption)
        let signed = try await s.sendAttachment(attachment, ts: ts())
        try await publish(signed.wire, kind: .message, itemHash: signed.hash, session: s)
        await store?.saveGroup(s)
        return signed
    }

    /// Registers a wake with every host of the group (deviations: wakes):
    /// when an item lands there, the host calls `url` with `handle`. An
    /// empty handle withdraws the member's registration. How many hosts
    /// took it.
    @discardableResult
    public func registerWake(url: String, handle: [UInt8], lifetimeMs: UInt64 = WakeRegistration.maxLifetimeMs,
                             in groupID: Hash32) async throws -> Int {
        let s = try session(groupID)
        let expires = handle.isEmpty ? 0 : ts() + min(lifetimeMs, WakeRegistration.maxLifetimeMs)
        var taken = 0
        for n in await s.hosts {
            guard let client = await directory.client(n) else { continue }
            let registration = WakeRegistration.sign(.init(memberPk: s.groupKey.publicKey, nodePk: n, groupID: groupID, url: url,
                                                           handle: handle, expires: expires), with: s.groupKey)
            do { try await client.registerWake(registration); taken += 1 } catch { log?("wake not taken by \(n.hex.prefix(8)): \(error)") }
        }
        return taken
    }

    /// An attachment's bytes, fetched from the first host that serves the
    /// blob and opened with the attachment's key.
    public func attachmentBytes(_ attachment: Attachment, in groupID: Hash32) async throws -> [UInt8] {
        let s = try session(groupID)
        for n in await s.hosts {
            guard let client = await directory.client(n), let sealed = try? await client.blob(groupID: groupID, hash: attachment.blob),
                  BlobSeal.name(of: sealed) == attachment.blob else { continue }
            return try BlobSeal.open(sealed, key: attachment.key)
        }
        throw Failure.noHosts
    }

    private func publish(_ bytes: [UInt8], kind: NodeAPI.ItemKind, itemHash: Hash32, session s: GroupSession) async throws {
        var hosts = HostPolicy.writeSet(await s.hosts, health: health, at: now())
        if hosts.isEmpty { hosts = await rendezvousNodes(for: s.groupID) }   // §13.1 fallback: RV(group_id)
        var receipted = 0
        for n in hosts {
            guard let client = await directory.client(n) else { continue }
            do {
                let receipt = try await client.send(bytes, kind: kind, groupID: s.groupID, itemHash: itemHash, expectedNode: n)
                // A stale `batch_prev` (D.5) means the node's claim about the batch is not pinned to its sequence.
                if let known = checkpoints[n], receipt.body.batchSeq == known.seq + 1, receipt.body.batchPrev != known.root {
                    health.record(n, success: false, at: now()); continue
                }
                await s.recordReceipt(receipt)
                health.record(n, success: true, at: now())
                receipted += 1
            } catch {
                health.record(n, success: false, at: now())
                log?("no receipt from \(n.hex.prefix(8)): \(error)")
            }
        }
        guard receipted > 0 else { throw Failure.noReceipt }
    }

    // MARK: fetching (§15–16)

    /// Fetches what the hosts hold that this client lacks, verifies, acks.
    @discardableResult
    public func pull(_ groupID: Hash32) async throws -> Int {
        let s = try session(groupID)
        var hosts = await s.hosts
        if health.healthy(hosts, at: now()).isEmpty { hosts = await rendezvousNodes(for: groupID) }
        var inserted = 0
        let have = await s.head == groupID ? Hash32.zero : await s.head
        for n in hosts {
            guard let client = await directory.client(n) else { continue }
            let request = FetchRequest.sign(.init(requesterPk: s.groupKey.publicKey, groupID: groupID, want: .range(sinceHead: have, head: Hash32.zero),
                                                  nonce: (0..<16).map { _ in UInt8.random(in: 0...255) }, time: ts()), with: s.groupKey)
            guard let (response, items) = try? await client.fetch(request) else { health.record(n, success: false, at: now()); continue }
            // §15: a response whose time is below the request's is no response.
            guard response.body.time >= request.body.time else { health.record(n, success: false, at: now()); continue }
            health.record(n, success: true, at: now())
            responsesByRequest[request.requestHash] = response
            await check(response, node: n, session: s)
            var deferred: [SignedMessage] = []
            for (hash, bytes) in items {
                if let signed = try? SignedMessage.fromWire(bytes), signed.hash == hash {
                    do { if try await s.receive(signed) { inserted += 1 } } catch DAG.InsertError.unknownParent { deferred.append(signed) } catch { continue }
                } else if let att = try? SignedAttestation.fromWire(bytes) {
                    await s.receive(att)
                } else { continue }
                let ack = Ack.sign(.init(recipientPk: s.groupKey.publicKey, nodePk: n, groupID: groupID, itemHash: hash, time: ts()), with: s.groupKey)
                try? await client.ack(ack)
            }
            var progress = true
            while progress, !deferred.isEmpty {
                progress = false
                for (i, signed) in deferred.enumerated().reversed() {
                    if (try? await s.receive(signed)) == true { inserted += 1; deferred.remove(at: i); progress = true }
                }
            }
        }
        await s.reopen()
        try? await judgeRepublishes(groupID)
        await store?.saveGroup(s)
        return inserted
    }

    /// §19: a member-only GET signed with the group's key now; nil when
    /// the group is unknown here.
    private func memberAuth(_ groupID: Hash32) async -> NodeClient.GetAuth? {
        guard let s = try? session(groupID) else { return nil }
        return .init(key: s.groupKey, time: ts())
    }

    /// Asks `node` for one receipted item and judges the answer (§17).
    public func probe(_ item: Hash32, in groupID: Hash32, node: PublicKey) async throws -> FetchStatus {
        let s = try session(groupID)
        guard let client = await directory.client(node) else { throw Failure.noHosts }
        let request = FetchRequest.sign(.init(requesterPk: s.groupKey.publicKey, groupID: groupID, want: .item(item),
                                              nonce: (0..<16).map { _ in UInt8.random(in: 0...255) }, time: ts()), with: s.groupKey)
        let (response, items) = try await client.fetch(request)
        // §15: a response whose time is below the request's is no response.
        guard response.body.time >= request.body.time else { health.record(node, success: false, at: now()); throw Failure.noResponse }
        if let receipt = await s.receipt(node: node, item: item) {
            let late = ts() > receipt.body.deadline
            if late { health.recordLateFetch(node, success: !items.isEmpty, at: now()) }
            if items.isEmpty, receipt.body.received <= response.body.time, response.body.time <= receipt.body.retainUntil {
                let genesis = response.body.status == FetchStatus.unauthorized.rawValue ? s.genesis.borsh : nil
                await report(.f1(receipt: receipt, request: request, response: response, genesis: genesis), node: node)
            }
        }
        await check(response, node: node, session: s)
        return FetchStatus(rawValue: response.body.status) ?? .notFound
    }

    /// F3 against every receipt held from this node, and F2 against a
    /// previous answer to the same request.
    private func check(_ response: FetchResponse, node: PublicKey, session s: GroupSession) async {
        for (hash, digest) in response.body.served {
            if let receipt = await s.receipt(node: node, item: hash), receipt.body.contentDigest != digest {
                await report(.f3(receipt: receipt, response: response), node: node)
            }
        }
        if let earlier = responsesByRequest[response.body.requestHash], earlier != response,
           case .success = FraudProof.f2(first: earlier, second: response).verify() {
            await report(.f2(first: earlier, second: response), node: node)
        }
    }

    /// Keeps a proof, marks the node, and gossips it to the nodes this
    /// client knows (§17), which pass it on.
    public func report(_ proof: FraudProof, node: PublicKey) async {
        guard case .success(let accused) = proof.verify(witnessQuorum: witnessQuorum), accused == node else { return }
        guard !fraudProofs.contains(proof) else { return }
        fraudProofs.append(proof)
        store?.saveFraud(proof)
        health.markFraudulent(node)
        log?("fraud F\(proof.tag) against \(node.hex.prefix(8))")
        var told = 0
        for other in await directory.known where other != node && told < 3 {
            if let client = await directory.client(other), (try? await client.submitFraud(proof)) != nil { told += 1 }
        }
    }

    /// Fetches the proofs a node holds against `suspect` and takes those
    /// that verify.
    public func learnFraud(against suspect: PublicKey, from node: PublicKey) async {
        guard let client = await directory.client(node), let proofs = try? await client.fraudProofs(against: suspect) else { return }
        for proof in proofs { await report(proof, node: suspect) }
    }

    // MARK: §6 commitments

    /// Whether a ref resolves: its batch proof against its own checkpoint,
    /// which carries a quorum of independent cosignatures.
    public func resolves(_ ref: CommitmentRef) -> Bool {
        guard ref.resolves(witnessQuorum: witnessQuorum) else { return false }
        observe(ref.checkpoint.checkpoint)
        return true
    }

    /// Notes a checkpoint of a node's log; one that contradicts another this
    /// client saw with the same `seq` is F6.
    private func observe(_ checkpoint: Checkpoint) {
        guard checkpoint.isSigned else { return }
        let node = checkpoint.nodePk
        if let known = checkpoints[node], known.seq == checkpoint.seq, known != checkpoint {
            let proof = FraudProof.f6(first: known, second: checkpoint, entries: [])
            Task { await self.report(proof, node: node) }
            return
        }
        if checkpoints[node].map({ checkpoint.seq > $0.seq }) ?? true { checkpoints[node] = checkpoint }
    }

    /// The newest witnessed checkpoint of a node's log held by the nodes
    /// this client knows (its own and its witnesses').
    public func checkpoint(of node: PublicKey) async -> WitnessedCheckpoint? {
        var best: WitnessedCheckpoint?
        for n in await directory.known {
            guard let client = await directory.client(n), let c = try? await client.checkpoint(node),
                  c.checkpoint.nodePk == node, c.checkpoint.isSigned else { continue }
            observe(c.checkpoint)
            if best.map({ c.checkpoint.seq > $0.checkpoint.seq || (c.checkpoint.seq == $0.checkpoint.seq && c.witnesses.count > $0.witnesses.count) }) ?? true {
                best = c
            }
        }
        return best
    }

    /// Republishes cite parent attestations; their sources resolve against
    /// the checkpoints they carry and are marked on the session.
    public func judgeRepublishes(_ groupID: Hash32) async throws {
        let s = try session(groupID)
        for ref in await s.unresolvedSources where resolves(ref) { await s.markResolved(ref) }
    }

    /// The commitment ref `node` itself serves for `item`, when it
    /// resolves (§6). For scoring a node on its own commitments, apart from
    /// whichever host's ref the session adopted for the item.
    public func commitment(of item: Hash32, at node: PublicKey, in groupID: Hash32) async -> CommitmentRef? {
        guard let client = await directory.client(node),
              let ref = try? await client.commitment(itemHash: item, auth: await memberAuth(groupID)), ref.nodePk == node else { return nil }
        return resolves(ref) ? ref : nil
    }

    /// Asks each receipting node for its `CommitmentRef` of every item
    /// still uncommitted; verified refs mark the item `committed`. Where a
    /// receipt is overdue and the node's published log has the promised
    /// batch without the item, builds and reports F4.
    @discardableResult
    public func syncCommitments(_ groupID: Hash32) async throws -> Int {
        let s = try session(groupID)
        var committed = 0
        let overdue = Set(await s.overdueReceipts(at: ts()).map { $0.body.preimage })
        // Items received from others carry no receipt here: any home node's
        // ref makes them `committed` too (§6, "any home node").
        let dag = await s.dag
        let held = Set(dag.messages.keys).union(dag.allAttestations.map(\.itemHash))
        let receipted = Set(await s.awaitingCommitment().map(\.item))
        for item in held where !dag.committed.contains(item) && !receipted.contains(item) {
            for node in await s.hosts {
                guard let client = await directory.client(node) else { continue }
                if let ref = try? await client.commitment(itemHash: item, auth: await memberAuth(groupID)), ref.nodePk == node, resolves(ref) {
                    await s.markCommitted(ref); committed += 1; break
                }
            }
        }
        try await judgeRepublishes(groupID)
        for (item, receipts) in await s.awaitingCommitment() {
            for receipt in receipts {
                let node = receipt.body.nodePk
                guard let client = await directory.client(node) else { continue }
                if let ref = try? await client.commitment(itemHash: item, auth: await memberAuth(receipt.body.groupID)), ref.nodePk == node, resolves(ref) {
                    await s.markCommitted(ref); committed += 1; break
                }
                // Published past the promised batch without the item: F4.
                guard overdue.contains(receipt.body.preimage) else { continue }
                if let checkpoint = try? await client.checkpoint(node), checkpoint.checkpoint.nodePk == node,
                   checkpoint.isPublished(quorum: witnessQuorum), checkpoint.checkpoint.seq >= receipt.body.batchSeq {
                    observe(checkpoint.checkpoint)
                    if let proof = await buildF4(receipt: receipt, client: client, checkpoint: checkpoint) { await report(proof, node: node) }
                    else { health.record(node, success: false, at: now()) }
                } else {
                    health.record(node, success: false, at: now())
                }
            }
        }
        if committed > 0 { await store?.saveGroup(s) }
        return committed
    }

    /// F4 from what the node itself serves: batch `s`'s body, the log's
    /// entries rebuilt to the checkpoint's size for the proofs of batches `s`
    /// and `s−1`, and the gap around the item in `s`.
    private func buildF4(receipt: Receipt, client: NodeClient, checkpoint: WitnessedCheckpoint) async -> FraudProof? {
        let seq = receipt.body.batchSeq
        guard let batch = try? await client.batch(receipt.body.nodePk, seq: seq), !batch.leaves.contains(receipt.body.itemHash),
              let (gi, _) = GapTree.gapLeaf(items: batch.leaves, around: receipt.body.itemHash) else { return nil }
        guard let leaves = try? await client.batchLeaves(receipt.body.nodePk) else { return nil }
        let history = Array(leaves.sorted { $0.seq < $1.seq }.compactMap(\.entry).prefix(Int(checkpoint.checkpoint.size)))
        let mmr = MMR(leaves: history.map(\.leaf))
        guard UInt64(history.count) == checkpoint.checkpoint.size, mmr.peaks == checkpoint.checkpoint.mmrPeaks else { return nil }
        func batchProof(_ n: UInt64) -> BatchProof? {
            guard n < UInt64(history.count), let proof = mmr.proof(index: Int(n)) else { return nil }
            return BatchProof(root: history[Int(n)].root, time: history[Int(n)].time, count: history[Int(n)].count, proof: proof)
        }
        guard let current = batchProof(seq) else { return nil }
        let previous = seq == 0 ? BatchProof(root: .zero, time: 0, count: 0, proof: MmrProof(size: 0, leafIndex: 0, siblings: [], peakIndex: 0)) : batchProof(seq - 1)
        guard let previous else { return nil }
        let proof = FraudProof.f4(receipt: receipt, checkpoint: checkpoint, batch: current, previous: previous, gap: GapProof(items: batch.leaves, index: gi))
        guard case .success = proof.verify(witnessQuorum: witnessQuorum) else { return nil }
        return proof
    }

    // MARK: §5 attesting

    /// Signs the head and publishes the attestation as an item.
    @discardableResult
    public func attest(_ groupID: Hash32) async throws -> SignedAttestation? {
        let s = try session(groupID)
        guard let signed = await s.attest() else { return nil }
        try await publish(signed.wire, kind: .attestation, itemHash: signed.itemHash, session: s)
        await s.noteAttested(at: ts())
        await store?.saveGroup(s)
        return signed
    }

    /// The client loop's one step for a group: pull, resolve commitments,
    /// attest when the cadence says so.
    public func maintain(_ groupID: Hash32) async throws {
        let s = try session(groupID)
        try await pull(groupID)
        try await syncCommitments(groupID)
        if await s.attestationDue(now: ts()) { _ = try await attest(groupID) }
    }

    // MARK: peers (§12)

    public func serve(_ groupID: Hash32, over channel: any DataChannel) async throws {
        let s = try session(groupID)
        for await frame in channel.incoming {
            guard frame.first == SyncFrame.request, let request = try? SyncRequest.fromWire(Array(frame.dropFirst())) else { continue }
            try await SyncResponder.serve(request, from: await s.dag, over: channel)
            return
        }
    }

    @discardableResult
    public func sync(_ groupID: Hash32, wantHead: Hash32, over channel: any DataChannel) async throws -> SyncClient.Outcome {
        let s = try session(groupID)
        let request = await s.syncRequest(wantHead: wantHead, missing: nil, time: ts())
        let outcome = try await s.withDAG { dag in try await SyncClient.request(request, into: &dag, over: channel) }
        await store?.saveGroup(s)
        return outcome
    }

    // MARK: forks (§9) and host changes (§13.1)

    public func hostChangeDue(_ groupID: Hash32) async -> Bool {
        guard let s = groups[groupID] else { return false }
        guard HostPolicy.hostChangeDue(await s.hosts, health: health, bounds: bounds, at: now()) else { hostChangeSince[groupID] = nil; return false }
        let since = hostChangeSince[groupID] ?? now()
        hostChangeSince[groupID] = since
        return now().timeIntervalSince(since) >= HostPolicy.forkDelay(memberIdx: s.memberIdx)
    }

    /// Begins a fork of `groupID` with the same identities (or `members`),
    /// hosts replaced per §13.1 when `reason` is `.hostChange`.
    public func beginFork(_ groupID: Hash32, members: [PublicKey]? = nil, reason: Genesis.Reason, forkHead: Hash32? = nil) async throws -> Hash32 {
        let parent = try session(groupID)
        var ids = members ?? []
        if members == nil { ids = await parent.identities }
        return try await beginCreation(members: ids, parent: parent, forkHead: forkHead, reason: reason)
    }

    /// Republishes this member's own committed messages past the fork
    /// point into the child (§9.4).
    @discardableResult
    public func republish(from parentID: Hash32, into childID: Hash32) async throws -> Int {
        let parent = try session(parentID), child = try session(childID)
        guard let ref = child.genesis.parent, ref.groupID == parentID else { throw Failure.unknownGroup }
        var count = 0
        for rp in await parent.republishes(after: ref.head) {
            let signed = try await child.republish(rp, ts: ts())
            try await publish(signed.wire, kind: .republish, itemHash: signed.hash, session: child)
            count += 1
        }
        await store?.saveGroup(child)
        return count
    }

    /// §9.6: re-sends this member's uncommitted parent messages as new
    /// messages in the child. Returns how many.
    @discardableResult
    public func rebase(from parentID: Hash32, into childID: Hash32) async throws -> Int {
        let parent = try session(parentID)
        var count = 0
        for text in await parent.uncommittedOwnTexts() {
            try await send(text, in: childID)
            count += 1
        }
        return count
    }
}
