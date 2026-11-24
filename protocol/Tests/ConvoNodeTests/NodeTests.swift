import ConvoCore
import ConvoNet
import Foundation
import Testing
@testable import ConvoNode
@testable import ConvoNodeCore

private func salt(_ n: UInt8) -> Hash32 { Hash32([UInt8](repeating: n, count: 32)) }

private struct Fixture {
    let keys: [SigningKey]
    let genesis: Genesis
    let node: ConvoNodeServer
    let signed: SignedMessage

    init(directory: String? = nil, nodeKey: SigningKey = SigningKey.random()) {
        let ids = (0..<3).map { try! SigningKey(seed: [UInt8](repeating: UInt8($0 + 1), count: 32)) }
        keys = ids.map { $0.groupKey(salt: salt(9)) }
        node = ConvoNodeServer(configuration: .init(id: "test", stateDirectory: directory), key: nodeKey,
                               ice: ICEProvider(mode: .none), fetch: { _, _, _ in (0, nil) })
        genesis = Genesis(salt: salt(9), members: keys.map(\.publicKey), quorum: 2, maxParents: 8, maxPayload: 65_536, maxUncommittedRepublish: 8, homeNodes: [node.nodePk, salt(0xa2)])
        let message = Message(groupID: genesis.groupID, authorIdx: 0, seq: 0, parents: [genesis.groupID], ts: 1, kind: .chat, payload: [1, 2, 3])
        signed = SignedMessage(message: message, signature: keys[0].sign(message.hash))
    }

    func request(_ method: String, _ path: String, _ body: [UInt8] = [], headers: [String: String] = [:]) -> HTTPResponse {
        node.respond(to: HTTPRequest(method: method, path: path, body: Data(body), headers: headers, peer: "127.0.0.1:1"))
    }

    /// A member-only GET (§19), signed at the node's time.
    func signedGet(_ path: String, key: SigningKey? = nil, time: UInt64? = nil) -> HTTPResponse {
        let signer = key ?? keys[0]
        let auth = NodeAPI.getAuth(key: signer, pathAndQuery: path, time: time ?? node.nowMs())
        return request("GET", path, headers: [NodeAPI.authHeader: auth])
    }

    func publishGenesis() { _ = request("POST", NodeAPI.genesis(genesis.groupID), GenesisRecord(genesis: genesis, carrySigs: []).wire) }

    /// A committer for this node whose witnesses are `witnesses`, in process.
    func committer(witnesses: [ConvoNodeServer]) async -> Committer {
        let committer = Committer(nodeKey: node.key, mailbox: node.mailbox)
        await committer.setWitnesses { witnesses.map { ($0.configuration.id, NodeClient(transport: InProcess(node: $0))) } }
        return committer
    }
}

private struct InProcess: NodeTransport {
    let node: ConvoNodeServer
    func request(_ method: String, _ path: String, body: [UInt8], contentType: String, headers: [String: String]) async throws -> (status: Int, body: [UInt8]) {
        let r = node.respond(to: HTTPRequest(method: method, path: path, body: Data(body), headers: headers, peer: "127.0.0.1:1"))
        return (r.status, Array(r.body))
    }
}

private func witnessNode(_ id: String) -> ConvoNodeServer {
    ConvoNodeServer(configuration: .init(id: id), key: SigningKey.random(), ice: ICEProvider(mode: .none), fetch: { _, _, _ in (0, nil) })
}

@Test func receiptBindsTheBytesAndNamesTheBatch() throws {
    let f = Fixture()
    let response = f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire)
    #expect(response.status == 200)
    let receipt = try Receipt.fromWire(Array(response.body))
    #expect(receipt.isValid)
    #expect(receipt.body.nodePk == f.node.nodePk)
    #expect(receipt.body.itemHash == f.signed.hash)
    #expect(receipt.body.contentDigest == Hashing.sha256(f.signed.wire))
    #expect(receipt.body.batchSeq == 0 && receipt.body.batchPrev == Hash32.zero)
    #expect(receipt.body.deadline == receipt.body.received + Parameters.Node.deliveryWindowMs)
    // The same bytes again: the same receipt, the same batch.
    let again = try Receipt.fromWire(Array(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire).body))
    #expect(again == receipt)
    #expect(f.node.mailbox.openCount == 1)
    // A message for another group at this path is refused; garbage too.
    #expect(f.request("POST", NodeAPI.item(salt(1), kind: .message), f.signed.wire).status == 400)
    #expect(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), [1, 2, 3]).status == 400)
}

@Test func fetchIsSignedMembersOnlyFoundOrNot() throws {
    let f = Fixture()
    _ = f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire)
    let time = f.node.nowMs()
    func fetch(_ key: SigningKey, want: FetchWant) throws -> FetchReply {
        let request = FetchRequest.sign(.init(requesterPk: key.publicKey, groupID: f.genesis.groupID, want: want, nonce: [UInt8](repeating: 1, count: 16), time: time), with: key)
        return try FetchReply.fromWire(Array(f.request("POST", NodeAPI.fetch(f.genesis.groupID), request.wire).body))
    }
    // No genesis held yet: nobody is a member.
    #expect(try fetch(f.keys[1], want: .item(f.signed.hash)).response.body.status == FetchStatus.unauthorized.rawValue)
    f.publishGenesis()
    let found = try fetch(f.keys[1], want: .item(f.signed.hash))
    #expect(found.response.isValid && found.response.body.status == FetchStatus.found.rawValue && found.items == [f.signed.wire])
    #expect(found.response.body.served.first?.1 == Hashing.sha256(f.signed.wire))
    let missing = try fetch(f.keys[1], want: .item(salt(7)))
    #expect(missing.response.isValid && missing.response.body.status == FetchStatus.notFound.rawValue && missing.items.isEmpty)
    let stranger = try fetch(SigningKey.random(), want: .item(f.signed.hash))
    #expect(stranger.response.isValid && stranger.response.body.status == FetchStatus.unauthorized.rawValue)
    // A range not under the held head is empty; from nothing, everything.
    #expect(try fetch(f.keys[2], want: .range(sinceHead: f.signed.hash, head: .zero)).items.isEmpty)
    #expect(try fetch(f.keys[2], want: .range(sinceHead: .zero, head: .zero)).items.count == 1)
}

@Test func genesisAttestationsAcksKeyPackagesAndInfo() throws {
    let f = Fixture()
    // A genesis naming another node as home is refused; this node's is kept and served.
    let elsewhere = Genesis(salt: salt(3), members: f.keys.map(\.publicKey), quorum: 2, maxParents: 8, maxPayload: 1, maxUncommittedRepublish: 1, homeNodes: [salt(0xa2)])
    #expect(f.request("POST", NodeAPI.genesis(elsewhere.groupID), GenesisRecord(genesis: elsewhere, carrySigs: []).wire).status == 403)
    #expect(f.request("POST", NodeAPI.genesis(f.genesis.groupID), GenesisRecord(genesis: f.genesis, carrySigs: []).wire).status == 204)
    #expect(try GenesisRecord.fromWire(Array(f.signedGet(NodeAPI.genesis(f.genesis.groupID)).body)).genesis == f.genesis)
    // Attestations are items too, listed with their commitment once posted.
    _ = f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire)
    var dag = DAG(genesis: f.genesis); try dag.insert(f.signed)
    let att = SignedAttestation.sign(Attestation(groupID: f.genesis.groupID, head: f.signed.hash, contentRoot: dag.contentRoot(under: f.signed.hash), msgCount: 1, signerIdx: 1), with: f.keys[1])
    #expect(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .attestation), att.wire).status == 200)
    let listed = try JSONDecoder().decode([AttestationRecord].self, from: f.signedGet(NodeAPI.attestations(f.genesis.groupID)).body)
    #expect(listed.count == 1 && listed[0].signed == att && listed[0].committed == nil)
    // Acks: only for this node, signed, and dated about now.
    let ackTime = UInt64(Date().timeIntervalSince1970 * 1000)
    let ack = Ack.sign(.init(recipientPk: f.keys[1].publicKey, nodePk: f.node.nodePk, groupID: f.genesis.groupID, itemHash: f.signed.hash, time: ackTime), with: f.keys[1])
    #expect(f.request("POST", NodeAPI.ack(f.genesis.groupID), ack.wire).status == 204)
    #expect(f.node.mailbox.pendingAcks.count == 1)
    let wrongNode = Ack.sign(.init(recipientPk: f.keys[1].publicKey, nodePk: salt(0xa2), groupID: f.genesis.groupID, itemHash: f.signed.hash, time: ackTime), with: f.keys[1])
    #expect(f.request("POST", NodeAPI.ack(f.genesis.groupID), wrongNode.wire).status == 400)
    // KeyPackages are receipted under the identity group and served back.
    let kpReceipt = try Receipt.fromWire(Array(f.request("POST", NodeAPI.keyPackage(salt(0x11)), [5, 6, 7]).body))
    #expect(kpReceipt.body.groupID == NodeAPI.identityGroup && kpReceipt.body.itemHash == Hashing.sha256([5, 6, 7]))
    #expect(Array(f.request("GET", NodeAPI.keyPackage(salt(0x11))).body) == [5, 6, 7])
    #expect(f.request("GET", NodeAPI.keyPackage(salt(0x12))).status == 404)
    let info = try JSONDecoder().decode(NodeInfo.self, from: f.request("GET", NodeAPI.info).body)
    #expect(info.publicKey == f.node.nodePk && info.turn == false && info.batchSeq == 0 && info.now != nil)
    #expect(info.descriptor?.operatorPk == f.node.nodePk)
    let health = try JSONDecoder().decode(HealthReport.self, from: f.request("GET", NodeAPI.health).body)
    #expect(health.ok && health.kind == "node")
}

@Test func rendezvousBoxesQueueAndExpire() {
    let f = Fixture()
    #expect(f.request("GET", "/rendezvous/box-12345").status == 404)
    #expect(f.request("POST", "/rendezvous/box-12345", Array("offer".utf8)).status == 200)
    #expect(f.request("POST", "/rendezvous/short", Array("x".utf8)).status == 400)
    #expect(String(decoding: f.request("GET", "/rendezvous/box-12345").body, as: UTF8.self) == "offer")
    #expect(f.request("GET", "/rendezvous/box-12345").status == 404)
}

@Test func batchesCheckpointWitnessAndProve() async throws {
    let dir = NSTemporaryDirectory() + "convo-node-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: dir) }
    let nodeKey = SigningKey.random()
    let f = Fixture(directory: dir, nodeKey: nodeKey)
    let witnesses = [witnessNode("w1"), witnessNode("w2")]
    let committer = await f.committer(witnesses: witnesses)
    f.publishGenesis()
    let receipt = try Receipt.fromWire(Array(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire).body))
    #expect(receipt.body.batchSeq == 0)
    #expect(f.signedGet(NodeAPI.commitment(f.signed.hash)).status == 404)
    let batch = try #require(await committer.commit())
    #expect(batch.seq == 0 && batch.leaves == [f.signed.hash].sorted() && batch.isValid)
    let checkpoint = try #require(f.node.mailbox.checkpoint)
    #expect(checkpoint.checkpoint.seq == 0 && checkpoint.checkpoint.root == batch.root && checkpoint.isPublished())
    #expect(checkpoint.witnesses == Set(witnesses.map(\.nodePk)))
    // The item's commitment resolves against the checkpoint it carries; the next receipt names batch 1 after this root.
    let ref = try CommitmentRef.decode(Array(f.signedGet(NodeAPI.commitment(f.signed.hash)).body))
    #expect(ref.batchSeq == 0 && ref.count == 1 && ref.resolves())
    let next = Message(groupID: f.genesis.groupID, authorIdx: 1, seq: 0, parents: [f.signed.hash], ts: 2, kind: .chat, payload: [4])
    let second = SignedMessage(message: next, signature: f.keys[1].sign(next.hash))
    let receipt2 = try Receipt.fromWire(Array(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), second.wire).body))
    #expect(receipt2.body.batchSeq == 1 && receipt2.body.batchPrev == batch.root)
    // Batch bodies, proofs, entries and checkpoints are served, by the node and its witnesses.
    #expect(try CommitmentBatch.fromWire(Array(f.request("GET", NodeAPI.batch(nodeKey.publicKey, seq: 0)).body)) == batch)
    let proof = try MmrProof.decode(Array(f.request("GET", NodeAPI.batchProof(nodeKey.publicKey, seq: 0)).body))
    #expect(MMR.verify(leaf: ref.mmrLeaf, proof: proof, peaks: checkpoint.checkpoint.mmrPeaks, size: 1) == 0)
    let served = try WitnessedCheckpoint.fromWire(Array(f.request("GET", NodeAPI.checkpoint(nodeKey.publicKey)).body))
    #expect(served == checkpoint)
    let held = try WitnessedCheckpoint.fromWire(Array(witnesses[0].respond(to: HTTPRequest(method: "GET", path: NodeAPI.checkpoint(nodeKey.publicKey), body: Data(), headers: [:], peer: "127.0.0.1:1")).body))
    #expect(held.checkpoint == checkpoint.checkpoint)
    let leaves = try JSONDecoder().decode([BatchLeaf].self, from: witnesses[1].respond(to: HTTPRequest(method: "GET", path: NodeAPI.batches(nodeKey.publicKey), body: Data(), headers: [:], peer: "127.0.0.1:1")).body)
    #expect(leaves.compactMap(\.entry) == [checkpoint.checkpoint.entry])
    // The second batch extends the log; the witnesses get only the new entry.
    let batch2 = try #require(await committer.commit())
    #expect(batch2.seq == 1 && f.node.mailbox.checkpoint?.checkpoint.seq == 1 && f.node.mailbox.isPublished(seq: 1))
    // Published items expire once past retention; a restart keeps the log, its checkpoint and the open sequence.
    #expect(f.node.mailbox.expire(now: UInt64.max) == 2)
    let reloaded = Mailbox(directory: dir + "/mailbox")
    #expect(reloaded.postedSeqs == [0, 1] && reloaded.openBatch.seq == 2 && reloaded.openBatch.prev == batch2.root)
    #expect(reloaded.checkpoint == f.node.mailbox.checkpoint)
    #expect(reloaded.genesis(groupID: f.genesis.groupID)?.genesis == f.genesis)
    // A foreign batch body is kept and served for its node, a fellow home of a
    // group held here (§13); a stranger's is refused.
    let other = SigningKey.random()
    let foreign = CommitmentBatch.sign(nodePk: other.publicKey, seq: 0, prevRoot: .zero, leaves: [salt(1)], with: other)
    #expect(f.request("POST", NodeAPI.batches(other.publicKey), foreign.wire).status == 403)
    let shared = Genesis(salt: salt(4), members: f.keys.map(\.publicKey), quorum: 2, maxParents: 8, maxPayload: 65_536,
                         maxUncommittedRepublish: 8, homeNodes: [f.node.nodePk, other.publicKey])
    _ = f.request("POST", NodeAPI.genesis(shared.groupID), GenesisRecord(genesis: shared, carrySigs: []).wire)
    #expect(f.request("POST", NodeAPI.batches(other.publicKey), foreign.wire).status == 204)
    #expect(try CommitmentBatch.fromWire(Array(f.request("GET", NodeAPI.batch(other.publicKey, seq: 0)).body)) == foreign)
}

/// Without witnesses a checkpoint is never published: nothing is committed
/// and nothing expires.
@Test func anUnwitnessedLogCommitsNothing() async throws {
    let f = Fixture()
    let committer = await f.committer(witnesses: [witnessNode("only")])
    f.publishGenesis()
    _ = f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire)
    _ = try #require(await committer.commit())
    #expect(f.node.mailbox.checkpoint?.isPublished() == false)
    #expect(f.signedGet(NodeAPI.commitment(f.signed.hash)).status == 404)
    #expect(f.node.mailbox.expire(now: UInt64.max) == 0)
}

@Test func omittedItemIsProvableAndFraudIsKeptAndServed() async throws {
    let nodeKey = SigningKey.random()
    let f = Fixture(nodeKey: nodeKey)
    let committer = await f.committer(witnesses: [witnessNode("w1"), witnessNode("w2")])
    // Two items receipted for batch 0; one is dropped before the batch closes.
    let receipt = try Receipt.fromWire(Array(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire).body))
    let other = Message(groupID: f.genesis.groupID, authorIdx: 1, seq: 0, parents: [f.genesis.groupID], ts: 2, kind: .chat, payload: [9])
    let kept = SignedMessage(message: other, signature: f.keys[1].sign(other.hash))
    _ = f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), kept.wire)
    f.node.mailbox.omitFromOpenBatch(f.signed.hash)
    let batch = try #require(await committer.commit())
    #expect(!batch.leaves.contains(f.signed.hash))
    let keptRef = try #require(f.node.mailbox.commitment(of: kept.hash))
    let (gi, _) = GapTree.gapLeaf(items: batch.leaves, around: f.signed.hash)!
    let f4 = FraudProof.f4(receipt: receipt, checkpoint: keptRef.checkpoint,
                           batch: BatchProof(root: keptRef.batchRoot, time: keptRef.time, count: keptRef.count, proof: keptRef.batchProof),
                           previous: BatchProof(root: .zero, time: 0, count: 0, proof: MmrProof(size: 0, leafIndex: 0, siblings: [], peakIndex: 0)),
                           gap: GapProof(items: batch.leaves, index: gi))
    #expect(f4.verify() == .success(nodeKey.publicKey))
    // Any node verifies, keeps and serves it; garbage is refused.
    let judge = witnessNode("judge")
    func ask(_ method: String, _ path: String, _ body: [UInt8] = []) -> HTTPResponse {
        judge.respond(to: HTTPRequest(method: method, path: path, body: Data(body), headers: [:], peer: "127.0.0.1:1"))
    }
    #expect(ask("POST", NodeAPI.fraud, f4.wire).status == 202)
    #expect(ask("POST", NodeAPI.fraud, [4, 0, 0]).status == 400)
    let held = try JSONDecoder().decode([String].self, from: ask("GET", NodeAPI.fraud(against: nodeKey.publicKey)).body)
    #expect(held == [f4.wire.hex])
    #expect(judge.mailbox.provenFaulty == [nodeKey.publicKey])
}

/// §11: a witness refuses a second history for the same log and holds F6.
@Test func aWitnessCatchesEquivocation() async throws {
    let node = SigningKey.random()
    let witness = witnessNode("w")
    let client = NodeClient(transport: InProcess(node: witness))
    let now = witness.nowMs()
    let a = LogEntry(root: salt(1), time: now, count: 1), b = LogEntry(root: salt(2), time: now, count: 1)
    let first = Checkpoint.sign(log: MMR(leaves: [a.leaf]), entry: a, with: node)
    guard case .cosigned(let c) = try await client.witness(WitnessRequest(checkpoint: first, fromSeq: 0, entries: [a])) else {
        Issue.record("first checkpoint refused"); return
    }
    #expect(c.witnessPk == witness.nodePk && c.verifies(first))
    // Resending from the wrong place says where to resume.
    let a2 = LogEntry(root: salt(3), time: now + 1, count: 2)
    let second = Checkpoint.sign(log: MMR(leaves: [a.leaf, a2.leaf]), entry: a2, with: node)
    #expect(try await client.witness(WitnessRequest(checkpoint: second, fromSeq: 0, entries: [a, a2])) == .conflict(size: 1, latest: WitnessedCheckpoint(checkpoint: first, cosignatures: [c])))
    // The same seq over another history: refused, and F6 kept.
    let forked = Checkpoint.sign(log: MMR(leaves: [b.leaf]), entry: b, with: node)
    guard case .conflict = try await client.witness(WitnessRequest(checkpoint: forked, fromSeq: 1, entries: [])) else {
        Issue.record("forked checkpoint cosigned"); return
    }
    #expect(witness.mailbox.provenFaulty == [node.publicKey])
    // A node never witnesses itself.
    #expect(witness.respond(to: HTTPRequest(method: "POST", path: NodeAPI.witness,
                                            body: Data(WitnessRequest(checkpoint: Checkpoint.sign(log: MMR(leaves: [a.leaf]), entry: a, with: witness.key), fromSeq: 0, entries: [a]).wire),
                                            headers: [:], peer: "127.0.0.1:1")).status == 400)
}

@Test func identityRecordsAreReceiptedAndServed() throws {
    let f = Fixture()
    let identity = SigningKey.random()
    let refs = [NodeRef(nodePk: f.node.nodePk, url: "https://node.example")]
    let older = IdentityRecord.sign(nodes: refs, updated: 1, with: identity)
    let newer = IdentityRecord.sign(nodes: refs, updated: 2, with: identity)
    let receipt = try Receipt.fromWire(Array(f.request("POST", NodeAPI.identity(identity.publicKey), newer.wire).body))
    #expect(receipt.isValid && receipt.body.groupID == NodeAPI.identityGroup && receipt.body.itemHash == Hashing.sha256(newer.wire))
    #expect(f.request("POST", NodeAPI.identity(identity.publicKey), older.wire).status == 409)
    #expect(f.request("POST", NodeAPI.identity(identity.publicKey), newer.wire).status == 200)
    #expect(f.request("POST", NodeAPI.identity(salt(4)), newer.wire).status == 400)
    #expect(try IdentityRecord.fromWire(Array(f.request("GET", NodeAPI.identity(identity.publicKey)).body)) == newer)
    #expect(f.request("GET", NodeAPI.identity(salt(4))).status == 404)
}

/// A browser preflights every byte POST; the node says yes to any path,
/// with the allow headers on every response (see the HTTP servers).
@Test func preflightIsAnsweredForEveryRoute() {
    let f = Fixture()
    #expect(f.request("OPTIONS", NodeAPI.genesis(f.genesis.groupID)).status == 204)
    #expect(f.request("OPTIONS", NodeAPI.fetch(f.genesis.groupID)).status == 204)
    #expect(f.request("OPTIONS", "/anything").status == 204)
    let head = String(decoding: HTTPParser.serialize(HTTPResponse(status: 204, body: Data())), as: UTF8.self)
    #expect(head.contains("Access-Control-Allow-Methods: GET, POST, OPTIONS"))
    #expect(head.contains("Access-Control-Allow-Headers: Content-Type, X-Convo-Auth"))
}

/// §13 retention beyond items: a body another node pushed goes once it
/// is `retention` old (a body loaded without a stamp counts from the
/// first pass).
@Test func retentionDropsOldForeignBodies() throws {
    let dir = NSTemporaryDirectory() + "convo-retention-" + UUID().uuidString
    let f = Fixture(directory: dir)
    let other = SigningKey.random()
    let batch = CommitmentBatch.sign(nodePk: other.publicKey, seq: 3, prevRoot: .zero, leaves: [salt(1)], with: other)
    try f.node.mailbox.storeForeign(batch, at: 100)
    #expect(f.node.mailbox.foreignSeqs(node: other.publicKey) == [3])
    #expect(f.node.mailbox.expire(now: 150, foreignRetention: 100) == 0)
    #expect(f.node.mailbox.foreignSeqs(node: other.publicKey) == [3])
    #expect(f.node.mailbox.expire(now: 201, foreignRetention: 100) == 1)
    #expect(f.node.mailbox.foreignSeqs(node: other.publicKey).isEmpty)
    #expect(!FileManager.default.fileExists(atPath: "\(dir)/foreign/\(other.publicKey.hex)/3.bin"))
    // A body on disk from before stamps existed: counted from the first pass.
    try FileManager.default.createDirectory(atPath: "\(dir)/foreign/\(other.publicKey.hex)", withIntermediateDirectories: true)
    let old = CommitmentBatch.sign(nodePk: other.publicKey, seq: 4, prevRoot: .zero, leaves: [salt(2)], with: other)
    try Data(old.wire).write(to: URL(fileURLWithPath: "\(dir)/foreign/\(other.publicKey.hex)/4.bin"))
    let reloaded = Mailbox(directory: dir)
    #expect(reloaded.foreignSeqs(node: other.publicKey) == [4])
    _ = reloaded.expire(now: 1_000, foreignRetention: 100)
    #expect(reloaded.foreignSeqs(node: other.publicKey) == [4])
    _ = reloaded.expire(now: 1_101, foreignRetention: 100)
    #expect(reloaded.foreignSeqs(node: other.publicKey).isEmpty)
    try? FileManager.default.removeItem(atPath: dir)
}


/// §19: member-only GETs need `X-Convo-Auth` from a member's group key at a
/// time near the node's.
@Test func memberOnlyGetsNeedASignedHeader() throws {
    let f = Fixture()
    f.publishGenesis()
    let path = NodeAPI.genesis(f.genesis.groupID)
    #expect(f.request("GET", path).status == 401)
    #expect(f.signedGet(path).status == 200)
    #expect(f.signedGet(path, key: SigningKey.random()).status == 401)          // not a member
    #expect(f.signedGet(path, time: f.node.nowMs() + NodeAPI.authWindowMs + 1_000).status == 401)      // outside the window
    // A header for one target does not open another.
    let other = NodeAPI.getAuth(key: f.keys[0], pathAndQuery: NodeAPI.attestations(f.genesis.groupID), time: f.node.nowMs())
    #expect(f.request("GET", path, headers: [NodeAPI.authHeader: other]).status == 401)
    // Public routes stay public.
    #expect(f.request("GET", NodeAPI.info).status == 200)
}

// MARK: wakes (deviations: wakes)

private final class RelayLog: @unchecked Sendable {
    let lock = NSLock()
    var calls: [(url: String, call: WakeCall)] = []
    func record(_ url: String, _ data: Data?) {
        guard let data, let call = try? JSONDecoder().decode(WakeCall.self, from: data) else { return }
        lock.lock(); calls.append((url, call)); lock.unlock()
    }
    func settled() -> [(url: String, call: WakeCall)] {
        for _ in 0..<200 {
            lock.lock(); let n = calls.count; lock.unlock()
            if n > 0 { Thread.sleep(forTimeInterval: 0.05); break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        lock.lock(); defer { lock.unlock() }; return calls
    }
}

@Test func wakesCallTheOtherMembersRelaysWhenAnItemLands() throws {
    let relay = RelayLog()
    let f = Fixture()
    f.node.fetch = { method, url, body in
        if method == "POST", url.hasPrefix("https://relay.example/") { relay.record(url, body) }
        return (204, nil)
    }
    f.publishGenesis()
    let current = f.node.nowMs()
    func register(_ i: Int, handle: [UInt8], expires: UInt64 = current + 1000, url: String = "https://relay.example/wake") -> Int {
        let body = WakeRegistration.Body(memberPk: f.keys[i].publicKey, nodePk: f.node.nodePk, groupID: f.genesis.groupID,
                                         url: url, handle: handle, expires: expires)
        return f.request("POST", NodeAPI.wake(f.genesis.groupID), WakeRegistration.sign(body, with: f.keys[i]).wire).status
    }
    #expect(register(0, handle: [0xa0]) == 204)
    #expect(register(1, handle: [0xb1, 0xb1]) == 204)
    #expect(register(2, handle: [0xc2], expires: current - 1) == 400)      // already past
    #expect(register(2, handle: [0xc2], url: "ftp://relay") == 400)         // not a web relay
    // A stranger, and a registration for another node, are refused.
    let stranger = SigningKey.random()
    let foreign = WakeRegistration.Body(memberPk: stranger.publicKey, nodePk: f.node.nodePk, groupID: f.genesis.groupID, url: "https://relay.example/x", handle: [1], expires: current + 10)
    #expect(f.request("POST", NodeAPI.wake(f.genesis.groupID), WakeRegistration.sign(foreign, with: stranger).wire).status == 403)
    let elsewhere = WakeRegistration.Body(memberPk: f.keys[2].publicKey, nodePk: salt(0xa2), groupID: f.genesis.groupID, url: "https://relay.example/x", handle: [1], expires: current + 10)
    #expect(f.request("POST", NodeAPI.wake(f.genesis.groupID), WakeRegistration.sign(elsewhere, with: f.keys[2]).wire).status == 400)
    #expect(f.node.wakes.count == 2)

    // Member 0 posts: member 1's relay is called (not member 0's own), with
    // the small item riding along, signed by the node.
    #expect(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire).status == 200)
    let calls = relay.settled()
    #expect(calls.count == 1)
    let call = try #require(calls.first?.call)
    #expect(call.handle == "b1b1")
    #expect(call.item == f.signed.hash.hex)
    #expect(call.signer == f.node.nodePk)
    #expect(call.body.flatMap { Data(base64Encoded: $0) }.map(Array.init) == f.signed.wire)
    // A tampered call does not verify.
    var forged = call; forged.handle = "a0"
    #expect(forged.signer == nil)

    // Withdrawn: an empty handle takes member 1's back, so member 2's
    // post wakes member 0 only.
    #expect(register(1, handle: []) == 204)
    #expect(f.node.wakes.count == 1)
    let next = Message(groupID: f.genesis.groupID, authorIdx: 2, seq: 0, parents: [f.signed.hash], ts: 2, kind: .chat, payload: [4])
    #expect(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), SignedMessage(message: next, signature: f.keys[2].sign(next.hash)).wire).status == 200)
    Thread.sleep(forTimeInterval: 0.15)
    let after = relay.settled()
    #expect(after.count == 2)
    #expect(after.last?.call.handle == "a0")
}

@Test func wakesSurviveARestartAndExpire() throws {
    let dir = NSTemporaryDirectory() + "convo-wakes-\(UUID().uuidString)"
    let nodeKey = SigningKey.random()
    let current: UInt64
    do {
        let f = Fixture(directory: dir, nodeKey: nodeKey)
        f.publishGenesis()
        current = f.node.nowMs()
        let body = WakeRegistration.Body(memberPk: f.keys[1].publicKey, nodePk: f.node.nodePk, groupID: f.genesis.groupID,
                                         url: "https://relay.example/wake", handle: [7], expires: current + 5)
        #expect(f.request("POST", NodeAPI.wake(f.genesis.groupID), WakeRegistration.sign(body, with: f.keys[1]).wire).status == 204)
    }
    let again = Fixture(directory: dir, nodeKey: nodeKey)
    #expect(again.node.wakes.count == 1)
    #expect(again.node.wakes.registrations(groupID: again.genesis.groupID, at: current + 4).count == 1)
    #expect(again.node.wakes.registrations(groupID: again.genesis.groupID, at: current + 5).isEmpty)
    #expect(again.node.wakes.expire(now: current + 5) == 1)
    #expect(again.node.wakes.count == 0)
}

/// One writer per key: the newest claim on a state directory wins, and an
/// instance that lost it refuses writes.
@Test func theNewestClaimHoldsTheStateDirectory() throws {
    let dir = NSTemporaryDirectory() + "convo-lease-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: dir) }
    let older = StateLease(directory: dir, id: "older", recheck: 0)
    try older.claim()
    #expect(older.confirm())
    #expect(older.holds())
    let newer = StateLease(directory: dir, id: "newer", recheck: 0)
    try newer.claim()
    #expect(newer.confirm())
    #expect(!older.holds() && newer.holds())
    // Lost for good, even if the file changes back.
    try Data("older 1\n".utf8).write(to: URL(fileURLWithPath: dir + "/owner"))
    #expect(!older.holds())

    let f = Fixture()
    let lost = Flag()
    f.node.mayWrite = { false }
    f.node.onLeaseLost = { lost.set() }
    #expect(f.request("POST", NodeAPI.item(f.genesis.groupID, kind: .message), f.signed.wire).status == 503)
    #expect(lost.isSet && f.node.mailbox.openCount == 0)
    #expect(f.request("GET", NodeAPI.health).status == 200)
}

private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
    func set() { lock.lock(); value = true; lock.unlock() }
}

/// State writes make their directory once and land whole.
@Test func stateFilesMakeTheirDirectoryAndWrite() throws {
    let dir = NSTemporaryDirectory() + "convo-state-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: dir) }
    try StateFiles.write([1, 2, 3], to: dir + "/a/b/x.bin")
    try StateFiles.write([4], to: dir + "/a/b/y.bin")
    #expect(FileManager.default.contents(atPath: dir + "/a/b/x.bin").map(Array.init) == [1, 2, 3])
    #expect(FileManager.default.contents(atPath: dir + "/a/b/y.bin").map(Array.init) == [4])
}

/// Rate limits count an IPv4 address or an IPv6 /64 as one client.
@Test func rateLimitsCountAnIPv6PrefixAsOneClient() {
    #expect(ConvoNodeServer.address(of: "203.0.113.7:51234") == "203.0.113.7")
    #expect(ConvoNodeServer.address(of: "[2001:db8:1:2:aaaa::1]:0") == "2001:db8:1:2::/64")
    #expect(ConvoNodeServer.address(of: "[2001:db8:1:2:bbbb:cccc:dddd:eeee]:443") == "2001:db8:1:2::/64")
    #expect(ConvoNodeServer.address(of: "[2001:db8:1:3::1]:0") != ConvoNodeServer.address(of: "[2001:db8:1:2::1]:0"))
    #expect(ConvoNodeServer.address(of: "[::1]:80") == "0:0:0:0::/64")
}

/// Past its storage budget a node takes nothing more for others; a genesis
/// no one uses or posts again goes after the retention period.
@Test func aNodeKeepsToItsBudgetAndDropsUnusedGeneses() throws {
    let key = SigningKey.random()
    let node = ConvoNodeServer(configuration: .init(id: "small", maxStoredBytes: 1_000), key: key,
                               ice: ICEProvider(mode: .none), fetch: { _, _, _ in (0, nil) })
    let members = (0..<2).map { _ in SigningKey.random().publicKey }
    func genesis(_ n: UInt8) -> Genesis {
        Genesis(salt: salt(n), members: members, quorum: 1, maxParents: 8, maxPayload: 1_024, maxUncommittedRepublish: 8, homeNodes: [node.nodePk])
    }
    func post(_ g: Genesis) -> Int {
        node.respond(to: HTTPRequest(method: "POST", path: NodeAPI.genesis(g.groupID), body: Data(GenesisRecord(genesis: g, carrySigs: []).wire),
                                     headers: [:], peer: "198.51.100.\(g.salt.bytes[0]):1")).status
    }
    var accepted = 0
    for n in UInt8(1)...UInt8(40) where post(genesis(n)) == 204 { accepted += 1 }
    #expect(accepted > 0 && accepted < 40)
    #expect(node.mailbox.storedBytes <= 1_000)
    #expect(post(genesis(41)) == 507)
    // Unused and never posted again: gone once the retention period has passed (counted from when it was posted).
    let posted = node.mailbox.genesis(groupID: genesis(1).groupID) != nil
    #expect(posted)
    node.mailbox.expire(now: UInt64(Date().timeIntervalSince1970 * 1000) + 10_000, foreignRetention: 60_000)
    #expect(node.mailbox.genesis(groupID: genesis(1).groupID) != nil)
    node.mailbox.expire(now: UInt64(Date().timeIntervalSince1970 * 1000) + 120_000, foreignRetention: 60_000)
    #expect(node.mailbox.genesis(groupID: genesis(1).groupID) == nil && node.mailbox.storedBytes == 0)
    #expect(post(genesis(41)) == 204)
}

/// An IPv4 client seen as IPv6 counts as its IPv4 address.
@Test func ipv4MappedClientsCountAsIPv4() {
    #expect(ConvoNodeServer.address(of: "[::ffff:203.0.113.7]:0") == "203.0.113.7")
    #expect(ConvoNodeServer.address(of: "[::ffff:cb00:7107]:0") == "203.0.113.7")
    #expect(ConvoNodeServer.address(of: "[::ffff:cb00:7108]:0") != ConvoNodeServer.address(of: "[::ffff:cb00:7107]:0"))
}

/// A genesis's posted time is kept on disk: a restart doesn't reset it, so
/// an unused one still goes after the retention period.
@Test func aGenesisPostedTimeSurvivesARestart() throws {
    let dir = NSTemporaryDirectory() + "genesis-time-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: dir) }
    let mailbox = Mailbox(directory: dir)
    let g = Genesis(salt: salt(7), members: [SigningKey.random().publicKey], quorum: 1, maxParents: 8, maxPayload: 1_024,
                    maxUncommittedRepublish: 8, homeNodes: [SigningKey.random().publicKey])
    try mailbox.storeGenesis(GenesisRecord(genesis: g, carrySigs: []), at: 1_000)
    let reloaded = Mailbox(directory: dir)
    #expect(reloaded.genesis(groupID: g.groupID) != nil)
    reloaded.expire(now: 1_000 + 120_000, foreignRetention: 60_000)
    #expect(reloaded.genesis(groupID: g.groupID) == nil)
    #expect(Mailbox(directory: dir).genesis(groupID: g.groupID) == nil)
}

/// An ack expires by its own time, so only one about now is taken, and no
/// group's acks take more than their share.
@Test func acksAreTakenOnlyNearNowAndPerGroup() {
    let f = Fixture()
    f.publishGenesis()
    let member = f.keys[0]
    func ack(_ time: UInt64, _ n: UInt8) -> Int {
        let body = Ack.Body(recipientPk: member.publicKey, nodePk: f.node.nodePk, groupID: f.genesis.groupID, itemHash: salt(n), time: time)
        return f.request("POST", NodeAPI.ack(f.genesis.groupID), Ack.sign(body, with: member).wire).status
    }
    let now = UInt64(Date().timeIntervalSince1970 * 1000)
    #expect(ack(now, 1) == 204)
    #expect(ack(now + 3_600_000, 2) == 400)
    #expect(ack(now - 3_600_000, 3) == 400)
    #expect(f.node.mailbox.pendingAcks.count == 1)
}
