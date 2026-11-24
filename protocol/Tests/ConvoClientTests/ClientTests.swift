import ConvoCore
import ConvoNet
import ConvoNode
import Foundation
import Testing
@testable import ConvoClient

/// Calls a node in process: no sockets, same handler the HTTP server uses.
struct InProcessTransport: NodeTransport {
    let node: ConvoNodeServer
    func request(_ method: String, _ path: String, body: [UInt8], contentType: String, headers: [String: String]) async throws -> (status: Int, body: [UInt8]) {
        let response = node.respond(to: HTTPRequest(method: method, path: path, body: Data(body), headers: headers, peer: "127.0.0.1:1"))
        return (response.status, Array(response.body))
    }
}

/// One clock for a world's nodes, committers and clients, so a test can
/// move them all ahead together (witnesses check a checkpoint's time).
final class WorldClock: @unchecked Sendable {
    private let lock = NSLock()
    private var offset: TimeInterval = 0
    func advance(by seconds: TimeInterval) { lock.lock(); offset += seconds; lock.unlock() }
    func date() -> Date { lock.lock(); defer { lock.unlock() }; return Date().addingTimeInterval(offset) }
    func ms() -> UInt64 { UInt64(date().timeIntervalSince1970 * 1000) }
}

/// Nodes that witness one another's logs, each with a committer; members
/// with KeyPackages published, directories pointing at every node.
struct World {
    let clock = WorldClock()
    let nodeKeys: [SigningKey]
    let nodes: [ConvoNodeServer]
    let committers: [Committer]
    let clients: [ConvoClient]
    let dirs: [String]

    init(members: Int = 3, nodeCount: Int = 3, persist: Bool = false) async throws {
        nodeKeys = (0..<nodeCount).map { i in try! SigningKey(seed: [UInt8](repeating: UInt8(0xa0 + i), count: 32)) }
        nodes = nodeKeys.enumerated().map { i, key in
            ConvoNodeServer(configuration: .init(id: "n\(i)"), key: key, ice: ICEProvider(mode: .none), fetch: { _, _, _ in (0, nil) })
        }
        let clock = self.clock
        for n in nodes { n.clock = { clock.date().timeIntervalSince1970 } }
        var committers: [Committer] = []
        for (i, n) in nodes.enumerated() {
            let c = Committer(nodeKey: nodeKeys[i], mailbox: n.mailbox, clock: { clock.ms() })
            let others = nodes.filter { $0.nodePk != n.nodePk }
            await c.setWitnesses { others.map { ($0.configuration.id, NodeClient(transport: InProcessTransport(node: $0))) } }
            committers.append(c)
            _ = i
        }
        self.committers = committers
        var clients: [ConvoClient] = []
        var dirs: [String] = []
        for i in 0..<members {
            let identity = try ConvoIdentity(seed: [UInt8](repeating: UInt8(i + 1), count: 32))
            let directory = NodeDirectory()
            for n in nodes { _ = try await directory.add(transport: InProcessTransport(node: n)) }
            let dir = NSTemporaryDirectory() + "convo-client-\(UUID().uuidString)"
            dirs.append(dir)
            let client = ConvoClient(identity: identity, name: "m\(i)", store: persist ? ClientStore(directory: dir) : nil, directory: directory)
            await client.setClock { clock.date() }
            try await client.publishKeyPackage()
            clients.append(client)
        }
        self.clients = clients
        self.dirs = dirs
    }

    func cleanup() { for d in dirs { try? FileManager.default.removeItem(atPath: d) } }

    /// Every node closes its open batch and has it witnessed.
    func commitAll() async {
        for c in committers { await c.commit() }
    }

    /// Moves every clock in the world `seconds` ahead.
    func advance(by seconds: TimeInterval) { clock.advance(by: seconds) }

    /// Past the time a receipted item must be committed by.
    static var pastCommitGrace: TimeInterval { Double(Parameters.Node.commitIntervalMs + Parameters.Client.commitGraceMs) / 1000 + 10 }

    /// Runs the handshake to completion: invite, announces, genesis, carries.
    func createGroup(by creator: Int, members: [Int], parent: Hash32? = nil, reason: Genesis.Reason = .root, forkHead: Hash32? = nil) async throws -> Hash32 {
        let ids = members.map { clients[$0].identity.publicKey }
        let parentSession: GroupSession? = if let parent { try await clients[creator].session(parent) } else { nil }
        let salt: Hash32
        if let parent { salt = try await clients[creator].beginFork(parent, members: ids, reason: reason, forkHead: forkHead) }
        else { salt = try await clients[creator].beginCreation(members: ids) }
        for m in members where m != creator {
            let pj: GroupSession? = if let parent { try? await clients[m].session(parent) } else { nil }
            _ = try await clients[m].join(salt: salt, parent: pj)   // invite → announce
        }
        let session = try await clients[creator].completeCreation(salt, parent: parentSession)   // announces → genesis
        let id = try #require(session?.groupID)
        for m in members where m != creator {
            let pj: GroupSession? = if let parent { try? await clients[m].session(parent) } else { nil }
            _ = try await clients[m].join(salt: salt, parent: pj)   // genesis (+ carry)
        }
        try await clients[creator].submitLateCarries(salt)
        return id
    }
}

@Test func handshakeSendPullAttestCommit() async throws {
    let w = try await World()
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    for c in w.clients { #expect(await c.groups[g] != nil) }
    let s0 = try await w.clients[0].session(g), s1 = try await w.clients[1].session(g)
    #expect(await s0.memberIdx == 0)
    #expect(s0.genesis.homeNodes.count == 3)
    // No transaction made the group; every home node holds its genesis.
    for n in w.nodes { #expect(n.mailbox.genesis(groupID: g)?.genesis == s0.genesis) }

    // Send from 0, pull at 1 and 2: same plaintext, receipts at every host naming batch 0.
    let sent = try await w.clients[0].send("hello", in: g)
    #expect(await s0.receipts.count == 3)
    #expect(await s0.receipts.values.allSatisfy { $0[sent.hash]?.body.batchSeq == 0 })
    #expect(try await w.clients[1].pull(g) == 1)
    #expect(try await w.clients[2].pull(g) == 1)
    #expect(await s1.entries().first?.text == "hello")
    #expect(w.nodes[0].mailbox.pendingAcks.count == 2)

    // 1 replies; 0 pulls; both see the same canonical order.
    try await w.clients[1].send("hi back", in: g)
    try await w.clients[0].pull(g)
    #expect(await s0.entries().map(\.text) == ["hello", "hi back"])
    #expect(await s0.head == s1.head)

    // Attestations by 0 and 1 (quorum 2 of 3) make the head `attested`; nothing waits on the nodes.
    _ = try await w.clients[0].attest(g)
    try await w.clients[1].pull(g)
    _ = try await w.clients[1].attest(g)
    try await w.clients[0].pull(g)
    #expect(await s0.entries().allSatisfy { $0.state == .attested })
    #expect(await s0.isAttested(sent.hash))

    // The nodes commit and witness each other; the clients resolve refs from them: `committed`.
    await w.commitAll()
    #expect(try await w.clients[0].syncCommitments(g) >= 2)
    #expect(await s0.entries().allSatisfy { $0.state == .committed })
    try await w.clients[2].pull(g)
    try await w.clients[2].syncCommitments(g)
    let s2 = try await w.clients[2].session(g)
    #expect(await s2.entries().allSatisfy { $0.state == .committed })
    // The attestations themselves were committed too.
    #expect(await s0.parentRef() != nil)
}

@Test func f1DeniedCustodyIsDetectedAndSubmitted() async throws {
    let w = try await World()
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    let sent = try await w.clients[0].send("keep this", in: g)
    await w.commitAll()
    // Node 0 loses the item after committing it: the probe's signed
    // not-found plus the receipt is F1; the client drops node 0 and tells
    // the other nodes, which keep the proof.
    _ = w.nodes[0].mailbox.expire(now: UInt64.max)
    let status = try await w.clients[0].probe(sent.hash, in: g, node: w.nodes[0].nodePk)
    #expect(status == .notFound)
    #expect(await w.clients[0].fraudProofs.count == 1)
    #expect(w.nodes[1].mailbox.provenFaulty == [w.nodes[0].nodePk] && w.nodes[2].mailbox.provenFaulty == [w.nodes[0].nodePk])
    #expect(await !w.clients[0].health.isHealthy(w.nodes[0].nodePk))
    #expect(try await w.clients[0].probe(sent.hash, in: g, node: w.nodes[1].nodePk) == .found)
    #expect(await w.clients[0].fraudProofs.count == 1)
}

@Test func f4OmittedFromThePromisedBatch() async throws {
    let w = try await World()
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    let sent = try await w.clients[0].send("promised", in: g)
    try await w.clients[1].send("also", in: g)
    // Node 1 publishes batch 0 without the receipted item.
    w.nodes[1].mailbox.omitFromOpenBatch(sent.hash)
    await w.commitAll()
    // Not yet overdue: no proof, just no commitment from node 1.
    try await w.clients[0].syncCommitments(g)
    #expect(await w.clients[0].fraudProofs.isEmpty)
    let s0 = try await w.clients[0].session(g)
    #expect(await s0.isCommitted(sent.hash))   // nodes 0 and 2 committed it
    // Past COMMIT_INTERVAL + COMMIT_GRACE the client could build F4 from node 1's own body and proofs.
    w.advance(by: World.pastCommitGrace)
    // The item is committed elsewhere, so its receipts leave the awaiting set.
    let overdue = await s0.overdueReceipts(at: w.clock.ms())
    #expect(overdue.contains { $0.body.nodePk == w.nodes[1].nodePk } == false)   // committed items leave the awaiting set
    // A fresh member with only node 1's receipt: send through node 1 alone.
    let lone = try await w.clients[2].session(g)
    _ = lone
    let single = try await w.clients[2].send("only to one", in: g)
    try await w.clients[0].send("filler so batch 1 is published", in: g)
    w.nodes[1].mailbox.omitFromOpenBatch(single.hash)
    w.nodes[0].mailbox.omitFromOpenBatch(single.hash)
    w.nodes[2].mailbox.omitFromOpenBatch(single.hash)
    await w.commitAll()
    w.advance(by: World.pastCommitGrace)
    try await w.clients[2].syncCommitments(g)
    let proofs = await w.clients[2].fraudProofs
    #expect(proofs.count == 3 && proofs.allSatisfy { $0.tag == 4 })
    for n in w.nodes { #expect(await !w.clients[2].health.isHealthy(n.nodePk)) }
    // Gossiped: each node holds the proofs against the other two.
    for n in w.nodes { #expect(n.mailbox.provenFaulty == Set(w.nodes.map(\.nodePk)).subtracting([n.nodePk])) }
}

@Test func peerSyncOverLoopback() async throws {
    let w = try await World(nodeCount: 3)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    try await w.clients[0].send("one", in: g)
    try await w.clients[0].send("two", in: g)
    let s0 = try await w.clients[0].session(g)
    let (a, b) = LoopbackChannel.pair()
    let head = await s0.head
    async let served: Void = w.clients[0].serve(g, over: a)
    let outcome = try await w.clients[1].sync(g, wantHead: head, over: b)
    try await served
    #expect(outcome.inserted.count == 2 && outcome.end == .complete)
    let s1 = try await w.clients[1].session(g)
    #expect(await s1.entries().map(\.text) == ["one", "two"])
}

@Test func forkWithCarryRepublishAndRebase() async throws {
    let w = try await World()
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    try await w.clients[0].send("before fork", in: g)
    for i in 0..<3 { try await w.clients[i].pull(g) }
    _ = try await w.clients[0].attest(g)
    try await w.clients[1].pull(g); _ = try await w.clients[1].attest(g)
    await w.commitAll()
    for i in 0..<3 { try await w.clients[i].syncCommitments(g) }
    let s0 = try await w.clients[0].session(g)
    let forkPoint = try #require(await s0.latestCommittedAttestedHead)
    // Past the fork point: one message committed under a committed attestation, one never committed.
    try await w.clients[0].send("after, committed", in: g)
    _ = try await w.clients[0].attest(g)
    await w.commitAll()
    try await w.clients[0].syncCommitments(g)
    try await w.clients[0].send("in flight", in: g)
    // Membership fork at the committed attested head: drop member 2. Carries from 0 and 1 reach the threshold → official.
    let child = try await w.createGroup(by: 0, members: [0, 1], parent: g, reason: .membership, forkHead: forkPoint)
    let cs = try await w.clients[0].session(child)
    #expect(cs.genesis.parent?.groupID == g && cs.genesis.parent?.head == forkPoint && cs.genesis.carry.count == 2)
    let record = try #require(w.nodes[0].mailbox.genesis(groupID: child))
    #expect(ForkAuthorization.isOfficial(child: cs.genesis, parentQuorum: s0.genesis.quorum, parentMembers: s0.genesis.members, carrySigs: record.carrySigs))
    #expect(try await w.clients[0].republish(from: g, into: child) == 1)
    #expect(try await w.clients[0].rebase(from: g, into: child) == 1)
    try await w.clients[1].pull(child)
    let c1 = try await w.clients[1].session(child)
    let entries = await c1.entries()
    #expect(entries.count == 2 && entries[0].kind == .republish && entries[1].text == "in flight")
    #expect(entries[0].republished?.verified == true)
    #expect(entries[0].republished?.original == 0)
}

@Test func storeRestoresSessionsAndKeepsRatchetMoving() async throws {
    let w = try await World(persist: true)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    try await w.clients[0].send("first", in: g)
    try await w.clients[1].pull(g)
    await w.commitAll()
    try await w.clients[0].syncCommitments(g)
    let directory = NodeDirectory()
    for n in w.nodes { _ = try await directory.add(transport: InProcessTransport(node: n)) }
    let store = ClientStore(directory: w.dirs[0])
    let restored = ConvoClient(identity: store.loadIdentity()!, name: store.name ?? "", store: store, directory: directory)
    await restored.load()
    let rs = try await restored.session(g)
    #expect(await rs.entries().map(\.text) == ["first"])
    #expect(await rs.receipts.count == 3)
    #expect(await rs.entries().first?.state == .committed)
    let second = try await restored.send("second", in: g)
    try await w.clients[1].pull(g)
    let s1 = try await w.clients[1].session(g)
    #expect(await s1.entries().map(\.text) == ["first", "second"])
    let first = try #require(await rs.message(await rs.entries()[0].hash))
    let g0 = try GroupPayload.decodeSealed(first.message.payload).generation
    #expect(try GroupPayload.decodeSealed(second.message.payload).generation == g0 + 1)
}

/// Two devices holding one identity (a handoff): what one seals, the
/// other reads, and neither seals at a generation the other used.
@Test func aSecondDeviceOfTheSameMemberNeverReusesAGeneration() async throws {
    let w = try await World(persist: true)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    try await w.clients[0].send("first", in: g)
    let directory = NodeDirectory()
    for n in w.nodes { _ = try await directory.add(transport: InProcessTransport(node: n)) }
    let store = ClientStore(directory: w.dirs[0])
    let phone = ConvoClient(identity: store.loadIdentity()!, name: store.name ?? "", store: store, directory: directory)
    await phone.load()
    let second = try await phone.send("second", in: g)
    // The original device pulls its own leaf's message from the hosts, reads
    // it, and moves past its generation before sealing again.
    try await w.clients[0].pull(g)
    let s0 = try await w.clients[0].session(g)
    #expect(await s0.entries().map(\.text) == ["first", "second"])
    let third = try await w.clients[0].send("third", in: g)
    let g2 = try GroupPayload.decodeSealed(second.message.payload).generation
    #expect(try GroupPayload.decodeSealed(third.message.payload).generation == g2 + 1)
    try await w.clients[1].pull(g)
    #expect(await (try w.clients[1].session(g)).entries().map(\.text) == ["first", "second", "third"])
}

/// The same leaf on two devices: an Update commit made on one is applied
/// by the other from the leaf secret sealed to their shared key, so both
/// keep reading and writing in the new epoch.
@Test func aSecondDeviceFollowsAnEpochRotation() async throws {
    let w = try await World(persist: true)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    try await w.clients[0].send("first", in: g)
    let directory = NodeDirectory()
    for n in w.nodes { _ = try await directory.add(transport: InProcessTransport(node: n)) }
    let store = ClientStore(directory: w.dirs[0])
    let phone = ConvoClient(identity: store.loadIdentity()!, name: store.name ?? "", store: store, directory: directory)
    await phone.load()
    let s0 = try await w.clients[0].session(g)
    try await w.clients[0].rotateEpoch(in: g)
    try await w.clients[0].send("after rotation", in: g)
    try await phone.pull(g)
    let ps = try await phone.session(g)
    #expect(await ps.mlsState?.epoch == 2)
    #expect(await ps.entries().filter { $0.kind == .chat }.map(\.text) == ["first", "after rotation"])
    try await phone.send("from the phone", in: g)
    try await w.clients[0].pull(g)
    #expect(await s0.entries().filter { $0.kind == .chat }.map(\.text) == ["first", "after rotation", "from the phone"])
    try await w.clients[1].pull(g)
    let s1 = try await w.clients[1].session(g)
    #expect(await s1.entries().filter { $0.kind == .chat }.map(\.text) == ["first", "after rotation", "from the phone"])
    #expect(await s1.mlsState?.epoch == 2)
}

/// `MLS_UPDATE_INTERVAL` on the clock: seven days after the epoch's first
/// own message an Update is due, and the store carries the clock.
@Test func epochUpdateIsDueOnTheClock() async throws {
    let w = try await World(persist: true)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    let s0 = try await w.clients[0].session(g)
    let day: UInt64 = 86_400_000
    let first = try await s0.send("first", ts: 10 * day)
    _ = first
    #expect(await !s0.epochUpdateDue(at: 16 * day))
    #expect(await s0.epochUpdateDue(at: 17 * day))
    await w.clients[0].store?.saveGroup(s0)
    let store = ClientStore(directory: w.dirs[0])
    let restored = try #require(await store.loadGroup(g, identity: store.loadIdentity()!))
    #expect(await restored.lastEpochUpdate == 10 * day)
    _ = try await s0.rotateEpoch(ts: 20 * day)
    #expect(await !s0.epochUpdateDue(at: 26 * day))
    _ = try await s0.send("again", ts: 21 * day)
    #expect(await !s0.epochUpdateDue(at: 26 * day))
    #expect(await s0.epochUpdateDue(at: 27 * day))
}

/// §9.2: an attestation over a head we do not hold marks us syncing (no
/// attesting) until the data arrives.
@Test func anAttestedHeadWeLackMeansSyncing() async throws {
    let w = try await World()
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    let s0 = try await w.clients[0].session(g), s1 = try await w.clients[1].session(g)
    let m = try await s0.send("only at 0", ts: 1)
    let att = try #require(await s0.attest())
    await s1.receive(att)
    #expect(await s1.isSyncing)
    #expect(await s1.unheldAttestedHeads == [m.hash])
    #expect(await s1.attest() == nil)
    try await s1.receive(m)
    #expect(await !s1.isSyncing)
    #expect(await s1.attest() != nil)
}

/// The app's shape of a handoff: members attest along the way, the clone
/// appears after attestations exist, and traffic keeps flowing both ways.
@Test func aSecondDeviceExchangesMessagesAfterAttestations() async throws {
    let w = try await World(persist: true)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    try await w.clients[1].send("hello there", in: g)
    try await w.clients[0].pull(g)
    _ = try await w.clients[0].attest(g); _ = try await w.clients[1].attest(g)
    let directory = NodeDirectory()
    for n in w.nodes { _ = try await directory.add(transport: InProcessTransport(node: n)) }
    let store = ClientStore(directory: w.dirs[0])
    let phone = ConvoClient(identity: store.loadIdentity()!, name: store.name ?? "", store: store, directory: directory)
    await phone.load()
    try await phone.pull(g)
    try await w.clients[1].send("second from b", in: g)
    _ = try await w.clients[1].attest(g)
    try await phone.pull(g)
    let ps = try await phone.session(g)
    #expect(await ps.entries().filter { $0.kind == .chat }.map(\.text) == ["hello there", "second from b"])
    try await phone.send("hi from the new device", in: g)
    try await w.clients[1].pull(g)
    let s1 = try await w.clients[1].session(g)
    #expect(await s1.entries().filter { $0.kind == .chat }.map(\.text) == ["hello there", "second from b", "hi from the new device"])
    try await w.clients[0].pull(g)
    let s0 = try await w.clients[0].session(g)
    #expect(await s0.entries().filter { $0.kind == .chat }.map(\.text) == ["hello there", "second from b", "hi from the new device"])
}

/// Two members send before either pulls: both branches show on both
/// sides, not only the one under the deeper (or smaller-hashed) head.
@Test func concurrentBranchesBothShow() async throws {
    let w = try await World()
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    try await w.clients[0].send("from 0", in: g)
    try await w.clients[1].send("from 1", in: g)
    try await w.clients[0].pull(g)
    try await w.clients[1].pull(g)
    let s0 = try await w.clients[0].session(g), s1 = try await w.clients[1].session(g)
    #expect(await s0.heads.count == 2)
    #expect(Set(await s0.entries().map(\.text)) == ["from 0", "from 1"])
    #expect(await s1.entries().map(\.text) == (await s0.entries().map(\.text)))
    try await w.clients[2].pull(g)
    let s2 = try await w.clients[2].session(g)
    #expect(await s2.entries().count == 2)
}

@Test func epochRotationKeepsPeersReading() async throws {
    let w = try await World(members: 2)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1])
    let s0 = try await w.clients[0].session(g)
    // A real timestamp: an Update dated at the epoch's dawn would make the
    // next one due on the clock at once.
    let update = try await s0.rotateEpoch(ts: UInt64(Date().timeIntervalSince1970 * 1000))
    #expect(update.message.kind == Message.Kind.control.rawValue)
    try await w.clients[0].send("after rotation", in: g)
    // The peer must apply the commit before the next message opens.
    let s1 = try await w.clients[1].session(g)
    try await s1.receive(update)
    try await w.clients[1].pull(g)
    #expect(await s1.entries().filter { $0.kind == .chat }.map(\.text) == ["after rotation"])
    let e0 = await s0.mlsState?.epoch, e1 = await s1.mlsState?.epoch
    #expect(e0 == 2 && e1 == 2)
}

@Test func hostChangeForkPicksReplacementsByRendezvous() async throws {
    let w = try await World(nodeCount: 5)
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1, 2])
    let c = w.clients[0]
    let s = try await c.session(g)
    let hosts = await s.hosts
    #expect(hosts.count == 4)   // TARGET_TOTAL_HOSTS = MIN_TOTAL + 1
    #expect(await !c.hostChangeDue(g))
    let t0 = Date()
    await c.setNow(t0)
    for h in hosts.prefix(3) { await c.recordFailure(h, at: t0.addingTimeInterval(-700)); await c.recordFailure(h, at: t0) }
    #expect(await c.hostChangeDue(g))   // member 0: no stagger
    let known = await c.knownNodes()
    let replacement = HostPolicy.replacementHosts(current: hosts, groupID: g, directory: known, health: await c.health, bounds: await c.bounds, at: t0)
    #expect(replacement.count == 2)
    #expect(replacement.contains(hosts[3]))
    #expect(!replacement.contains(hosts[0]) && !replacement.contains(hosts[1]) && !replacement.contains(hosts[2]))
}

/// §13.2: an identity names its nodes; others find its KeyPackage there.
@Test func identityRecordsPointAtAnIdentitysNodes() async throws {
    let w = try await World(members: 2, nodeCount: 5)
    defer { w.cleanup() }
    let own = w.nodes[4].nodePk
    let record = try await w.clients[0].publishIdentity(nodes: [own])
    #expect(record.nodes.map(\.nodePk) == [own] && w.nodes[4].mailbox.identity(w.clients[0].identity.publicKey) == record)
    try await w.clients[0].publishKeyPackage()
    #expect(w.nodes[4].mailbox.keyPackage(identity: w.clients[0].identity.publicKey) != nil)
    // The other member learns the record from RV(id_pk) and asks its nodes first.
    let nodes = await w.clients[1].identityNodes(for: w.clients[0].identity.publicKey)
    #expect(nodes.first == own)
    #expect(await w.clients[1].identityRecords[w.clients[0].identity.publicKey] == record)
}

extension ConvoClient {
    func setNow(_ date: Date) { now = { date } }
    func setClock(_ clock: @escaping @Sendable () -> Date) { now = clock }
    func recordFailure(_ node: PublicKey, at: Date) { recordHealth(node, success: false, at: at) }
}


/// Kinds 3 and 4 (Docs/deviations.md): a reaction folds onto its target and
/// a removal takes it back; an attachment's blob round-trips through the
/// hosts sealed, and only the group opens it.
@Test func reactionsFoldAndAttachmentsRoundTrip() async throws {
    let w = try await World()
    defer { w.cleanup() }
    let g = try await w.createGroup(by: 0, members: [0, 1])
    let s0 = try await w.clients[0].session(g), s1 = try await w.clients[1].session(g)
    let sent = try await w.clients[0].send("a picture is coming", in: g)
    _ = try await w.clients[1].pull(g)

    _ = try await w.clients[1].react(to: sent.hash, emoji: "👍", in: g)
    _ = try await w.clients[0].pull(g)
    #expect(await s0.reactions(on: sent.hash).map { ($0.emoji, $0.authors) }.elementsEqual([("👍", [1])], by: { $0.0 == $1.0 && $0.1 == $1.1 }))
    // Reactions are not thread entries of their own kind for a reader of chat.
    #expect(await s0.entries().filter { $0.kind == .chat }.count == 1)
    _ = try await w.clients[1].react(to: sent.hash, emoji: "👍", remove: true, in: g)
    _ = try await w.clients[0].pull(g)
    #expect(await s0.reactions(on: sent.hash).isEmpty)

    let picture: [UInt8] = (0..<5_000).map { UInt8(truncatingIfNeeded: $0 &* 31) }
    let attached = try await w.clients[0].sendAttachment(picture, mime: "image/jpeg", width: 40, height: 30, caption: "hi", in: g)
    _ = try await w.clients[1].pull(g)
    let entry = try #require(await s1.entries().first { $0.hash == attached.hash })
    let attachment = try #require(entry.attachment)
    #expect(entry.kind == .attachment && attachment.mime == "image/jpeg" && attachment.width == 40 && attachment.caption == "hi")
    #expect(try await w.clients[1].attachmentBytes(attachment, in: g) == picture)
    // The blob at the host is sealed: not the picture, and named by its sealed bytes.
    let held = try #require(w.nodes[0].mailbox.blob(groupID: g, hash: attachment.blob))
    #expect(held.bytes != picture && Hashing.sha256(held.bytes) == attachment.blob)
}
