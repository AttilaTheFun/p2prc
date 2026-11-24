import ConvoCore
import Foundation
import Testing

/// Appendix A.6: the test vectors under Tests/Vectors, generated from fixed
/// seeds. Ed25519 signing is randomized on Apple platforms (CryptoKit), so
/// a signature cannot be reproduced; the vectors carry the signatures, and
/// conformance means: from these bytes and signatures, derive every hash,
/// root, proof and verdict byte for byte, and accept every signature. The
/// first run writes the files; later runs check against them. Delete the
/// directory to regenerate (and bump the protocol version).
@Suite struct VectorTests {
    static let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Vectors")

    static func load(_ name: String) -> [String: Any]? {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent(name)) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    static func write(_ name: String, _ object: [String: Any]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: directory.appendingPathComponent(name))
    }

    /// Compares every key except the signature-bearing ones, which are
    /// checked by verification instead.
    static func expectSame(_ produced: [String: Any], _ stored: [String: Any], file: String) {
        let skip: Set<String> = ["msg_sig", "att_sig", "sig", "carry_sigs", "wire", "batch_sig", "checkpoint_wire", "short_checkpoint_wire"]
        for (key, value) in produced where !skip.contains(key) {
            let a = try? JSONSerialization.data(withJSONObject: [key: value], options: [.sortedKeys])
            let b = try? JSONSerialization.data(withJSONObject: [key: stored[key] ?? NSNull()], options: [.sortedKeys])
            #expect(a == b, "\(file).\(key) differs")
        }
    }

    static func check(_ name: String, _ produced: [String: Any]) throws {
        if let stored = load(name) { expectSame(produced, stored, file: name) } else { try write(name, produced) }
    }

    static func steps(_ proof: [Merkle.ProofStep]) -> [[String: Any]] { proof.map { ["sibling": $0.sibling.hex, "side": Int($0.side)] } }

    /// A stored signature for `key` in `file`, else a fresh one.
    static func sig(_ file: [String: Any]?, _ key: String, _ path: [String] = [], make: () -> [UInt8]) -> [UInt8] {
        var node: Any? = file
        for p in path { node = (node as? [String: Any])?[p] }
        if let hex = (node as? [String: Any])?[key] as? String, let bytes = [UInt8](hex: hex) { return bytes }
        return make()
    }

    /// A stored witnessed checkpoint under `key` in `file`, else a fresh one.
    static func checkpoint(_ file: [String: Any]?, _ key: String, make: () -> WitnessedCheckpoint) -> WitnessedCheckpoint {
        if let hex = file?[key] as? String, let bytes = [UInt8](hex: hex), let c = try? WitnessedCheckpoint.fromWire(bytes) { return c }
        return make()
    }

    @Test func identityVector() throws {
        let words = Array(repeating: "abandon", count: 11) + ["about"]
        let key = try IdentityKey.key(words: words)
        let v: [String: Any] = ["mnemonic": words.joined(separator: " "), "seed": Mnemonic.seed(words: words).hex,
                                "derivation": "HKDF-SHA256(ikm=seed, salt=\"convo\", info=\"convo/identity/v1\", 32)",
                                "id_sk": key.seed.hex, "id_pk": key.publicKey.hex,
                                "gk_salt": Fixtures.salt.hex, "gk_pk": key.groupKey(salt: Fixtures.salt).publicKey.hex,
                                "hpke_seed": (0..<3).map { key.hpkeSeed(index: UInt32($0)).hex }]
        try Self.check("identity.json", v)
    }

    @Test func partOneVectors() throws {
        let ms = Fixtures.members(3)
        let g = Fixtures.genesis(ms)
        let storedMessages = Self.load("messages.json")
        let storedAttestation = Self.load("attestation.json")
        let storedGenesis = Self.load("genesis.json")

        func signed(_ key: String, _ m: Message, _ author: Int) -> SignedMessage {
            SignedMessage(message: m, signature: Self.sig(storedMessages, "msg_sig", [key]) { ms[author].groupKey.sign(m.hash) })
        }
        var dag = DAG(genesis: g)
        let m1 = signed("m1", Fixtures.message(g, author: 0, seq: 0, parents: [g.groupID], ts: 1_700_000_000_000, payload: Array("hello".utf8)), 0)
        try dag.insert(m1)
        let m2 = signed("m2", Fixtures.message(g, author: 1, seq: 0, parents: [m1.hash], ts: 1_700_000_001_000, payload: Array("hi".utf8)), 1)
        let m3 = signed("m3", Fixtures.message(g, author: 2, seq: 0, parents: [m1.hash], ts: 1_700_000_001_000, payload: Array("hey".utf8)), 2)
        try dag.insert(m2); try dag.insert(m3)
        let m4 = signed("m4", Fixtures.message(g, author: 0, seq: 1, parents: [m2.hash, m3.hash], ts: 1_700_000_002_000, payload: Array("all".utf8)), 0)
        try dag.insert(m4)
        let all = [m1, m2, m3, m4]
        var messages: [String: Any] = [:]
        for (i, m) in all.enumerated() {
            messages["m\(i + 1)"] = ["borsh": m.message.borsh.hex, "msg_hash": m.hash.hex, "msg_sig": m.signature.hex, "leaf": m.leaf.hex, "wire": m.wire.hex]
        }
        if let stored = storedMessages {
            for (k, v) in messages { Self.expectSame(v as! [String: Any], stored[k] as! [String: Any], file: "messages.\(k)") }
        } else { try Self.write("messages.json", messages) }
        for m in all { #expect(m.verify(author: g.members[Int(m.message.authorIdx)])) }

        let head = m4.hash
        let order = dag.canonicalOrder(under: head)
        let root = dag.contentRoot(under: head)
        try Self.check("order.json", ["head": head.hex, "canonical_order": order.map(\.hex), "content_root": root.hex,
                                       "proofs": order.map { Self.steps(dag.inclusionProof(of: $0, under: head)!) }])

        let att = Attestation(groupID: g.groupID, head: head, contentRoot: root, msgCount: 4, signerIdx: 1)
        let attSig = Self.sig(storedAttestation, "att_sig") { ms[1].groupKey.sign(att.preimage) }
        #expect(Signature.verify(attSig, hash: att.preimage, publicKey: g.members[1]))
        let signedAtt = SignedAttestation(attestation: att, signature: attSig)
        try Self.check("attestation.json", ["borsh": att.borsh.hex, "item_hash": att.itemHash.hex, "att_sig": attSig.hex, "wire": signedAtt.wire.hex])

        // A node commits the attestation; the child cites it.
        let node = Fixtures.nodeKeys[0]
        let (batches, times, mmr) = Fixtures.commitments(node: node, batches: [[m1.hash, m2.hash], [att.itemHash, m3.hash, m4.hash]])
        let storedRef = Self.load("commitment_ref.json")
        let checkpoint = Self.checkpoint(storedRef, "checkpoint_wire") { Fixtures.checkpoint(node: node, batches: batches, times: times) }
        let source = batches[1].reference(item: att.itemHash, time: times[1], mmr: mmr, checkpoint: checkpoint)!
        let childSalt = Hash32([UInt8](repeating: 0x7c, count: 32))
        let childMembers = [0, 1].map { i in Fixtures.Member(identity: ms[i].identity, groupKey: ms[i].identity.groupKey(salt: childSalt)) }
        let ref = ParentRef(groupID: g.groupID, head: head, source: source)
        let child = Fixtures.genesis(childMembers, salt: childSalt, parent: ref, carry: [(0, 0), (1, 1)], reason: .membership)
        let forkHash = ForkAuthorization.preimage(parent: g.groupID, child: child.groupID)
        let carrySigs: [[String: Any]] = (storedGenesis?["carry_sigs"] as? [[String: Any]]) ?? [0, 1].map { ["parent_idx": $0, "sig": ms[$0].groupKey.sign(forkHash).hex] }
        let verified = ForkAuthorization.verify(child: child, parentMembers: g.members, carrySigs: carrySigs.map { (UInt8($0["parent_idx"] as! Int), [UInt8](hex: $0["sig"] as! String)!) })
        #expect(verified == [0, 1])
        try Self.check("genesis.json", ["version": Int(g.version), "seeds": ms.map { $0.identity.seed.hex }, "salt": g.salt.hex,
                                         "gk": ms.map { $0.groupKey.publicKey.hex }, "genesis_borsh": g.borsh.hex, "group_id": g.groupID.hex,
                                         "child_borsh": child.borsh.hex, "child_group_id": child.groupID.hex, "fork_preimage": forkHash.hex,
                                         "carry_sigs": carrySigs, "threshold": ForkAuthorization.threshold(parentQuorum: g.quorum, carryCount: 2)])

        var tampered = source; tampered.itemProof[0] = Merkle.ProofStep(sibling: Hash32.zero, side: tampered.itemProof[0].side)
        var unwitnessed = source; unwitnessed.checkpoint.cosignatures = Array(unwitnessed.checkpoint.cosignatures.prefix(1))
        try Self.check("commitment_ref.json", ["checkpoint_wire": checkpoint.wire.hex, "checkpoint_preimage": checkpoint.checkpoint.preimage.hex,
                                                "log_size": Int(checkpoint.checkpoint.size), "mmr_peaks": checkpoint.checkpoint.mmrPeaks.map(\.hex),
                                                "witnesses": checkpoint.witnesses.map(\.hex).sorted(), "published": checkpoint.isPublished(quorum: 2),
                                                "ref_borsh": source.borsh.hex, "resolves": source.resolves(witnessQuorum: 2),
                                                "tampered_borsh": tampered.borsh.hex, "tampered_resolves": tampered.resolves(witnessQuorum: 2),
                                                "one_witness_resolves": unwitnessed.resolves(witnessQuorum: 2)])

        let rp = Republish(parentGroupID: g.groupID, source: source, attestation: signedAtt, original: m2, inclusionProof: dag.inclusionProof(of: m2.hash, under: head)!)
        try Self.check("republish.json", ["borsh": rp.borsh.hex, "verifies": rp.verify(parentMembers: g.members, witnessQuorum: 2)])
    }

    @Test func commitmentVectors() throws {
        let node = Fixtures.nodeKeys[0]
        let items = [5, 1, 3, 3, 9].map { Hash32([UInt8](repeating: UInt8($0), count: 32)) }
        let leaves = GapTree.leaves(items: items)
        let root = GapTree.root(items: items)
        let three = Hash32([UInt8](repeating: 3, count: 32)), four = Hash32([UInt8](repeating: 4, count: 32))
        let (mi, mleaf) = GapTree.membershipLeaf(items: items, item: three)!
        let (ni, nleaf) = GapTree.gapLeaf(items: items, around: four)!
        let (bi, bleaf) = GapTree.gapLeaf(items: items, around: Hash32([UInt8](repeating: 0, count: 31) + [1]))!
        let stored = Self.load("cbatch.json")
        let batchSig = Self.sig(stored, "batch_sig") { node.sign(CommitmentBatch.preimage(nodePk: node.publicKey, seq: 0, prevRoot: .zero, root: root)) }
        let batch = CommitmentBatch(nodePk: node.publicKey, seq: 0, prevRoot: .zero, leaves: items, signature: batchSig)
        #expect(batch.isValid)
        var cb: [String: Any] = ["items": items.map { $0.hex }, "sorted": GapTree.sorted(items).map { $0.hex }, "root": root.hex]
        cb["gap_leaves"] = leaves.map { ["lo": $0.lo.hex, "hi": $0.hi.hex, "hash": $0.hash.hex] as [String: Any] }
        let mProof: [[String: Any]] = Self.steps(GapTree.proof(items: items, leafIndex: mi))
        let nProof: [[String: Any]] = Self.steps(GapTree.proof(items: items, leafIndex: ni))
        let mLeaf: [String: String] = ["lo": mleaf.lo.hex, "hi": mleaf.hi.hex]
        let nLeaf: [String: String] = ["lo": nleaf.lo.hex, "hi": nleaf.hi.hex]
        let bLeaf: [String: String] = ["lo": bleaf.lo.hex, "hi": bleaf.hi.hex]
        var membership: [String: Any] = ["item": three.hex, "leaf_index": mi]
        membership["leaf"] = mLeaf; membership["proof"] = mProof
        var nonMembership: [String: Any] = ["item": four.hex, "leaf_index": ni]
        nonMembership["leaf"] = nLeaf; nonMembership["proof"] = nProof
        var boundary: [String: Any] = ["leaf_index": bi]
        boundary["leaf"] = bLeaf
        // Rev2 A.5: the path must have the shape (index, leaf_count) dictates.
        let mPath = GapTree.proof(items: items, leafIndex: mi)
        membership["leaf_count"] = leaves.count
        membership["shape_verifies"] = Merkle.verify(leaf: mleaf.hash, proof: mPath, root: root, index: mi, count: leaves.count, nodeTag: Domain.gapNode)
        let truncated = Array(mPath.dropLast())
        var wrongShape: [String: Any] = ["item": three.hex, "leaf_index": mi, "leaf_count": leaves.count]
        wrongShape["proof"] = Self.steps(truncated)
        wrongShape["verifies"] = Merkle.verify(leaf: mleaf.hash, proof: truncated, root: root, index: mi, count: leaves.count, nodeTag: Domain.gapNode)
        cb["wrong_shape"] = wrongShape
        cb["membership"] = membership
        cb["non_membership"] = nonMembership
        cb["boundary"] = boundary
        cb["batch_preimage"] = CommitmentBatch.preimage(nodePk: node.publicKey, seq: 0, prevRoot: .zero, root: root).hex
        cb["batch_sig"] = batchSig.hex
        cb["batch_wire"] = batch.wire.hex
        try Self.check("cbatch.json", cb)

        var mmr = MMR()
        var peaks: [String: Any] = [:]
        var leafHashes: [Hash32] = []
        for i in 0..<8 {
            let root = Hash32([UInt8](repeating: UInt8(0x10 + i), count: 32))
            leafHashes.append(MMR.leaf(root: root, time: UInt64(1_700_000_000_000 + 300_000 * i), count: UInt64(i + 1)))
        }
        for (n, leaf) in leafHashes.enumerated() {
            mmr.append(leaf)
            if [1, 2, 3, 7, 8].contains(n + 1) { peaks["after_\(n + 1)"] = mmr.peaks.map(\.hex) }
        }
        let seven = MMR(leaves: Array(leafHashes.prefix(7)))
        let p2of7 = seven.proof(index: 2)!, p5of8 = mmr.proof(index: 5)!
        var negative = p5of8; negative.peakIndex = 0
        var mv: [String: Any] = ["leaves": leafHashes.map { $0.hex }, "peaks": peaks]
        mv["proof_2_of_7"] = ["size": Int(p2of7.size), "leaf_index": Int(p2of7.leafIndex), "siblings": Self.steps(p2of7.siblings), "peak_index": Int(p2of7.peakIndex), "verifies": MMR.verify(leaf: leafHashes[2], proof: p2of7, peaks: seven.peaks, size: 7) == 2] as [String: Any]
        mv["proof_5_of_8"] = ["size": Int(p5of8.size), "leaf_index": Int(p5of8.leafIndex), "siblings": Self.steps(p5of8.siblings), "peak_index": Int(p5of8.peakIndex), "verifies": MMR.verify(leaf: leafHashes[5], proof: p5of8, peaks: mmr.peaks, size: 8) == 5] as [String: Any]
        // Rev2 A.4: the same leaf re-proved at size 8, and the size-7 proof
        // refused against the size-8 peaks (it names its size).
        let p2of8 = mmr.proof(index: 2)!
        mv["proof_2_of_8"] = ["size": Int(p2of8.size), "leaf_index": Int(p2of8.leafIndex), "siblings": Self.steps(p2of8.siblings), "peak_index": Int(p2of8.peakIndex),
                              "verifies": MMR.verify(leaf: leafHashes[2], proof: p2of8, peaks: mmr.peaks, size: 8) == 2,
                              "stale_2_of_7_verifies_at_8": MMR.verify(leaf: leafHashes[2], proof: p2of7, peaks: mmr.peaks, size: 8) != nil] as [String: Any]
        mv["negative"] = ["peak_index": Int(negative.peakIndex), "verifies": MMR.verify(leaf: leafHashes[5], proof: negative, peaks: mmr.peaks, size: 8) != nil] as [String: Any]
        try Self.check("mmr.json", mv)
    }

    @Test func partTwoAndBorshVectors() throws {
        let node = try SigningKey(seed: Fixtures.seed(0x77))
        let member = Fixtures.members(1)[0].groupKey
        let group = Hash32([UInt8](repeating: 1, count: 32)), item = Hash32([UInt8](repeating: 2, count: 32))
        let d0 = Hash32([UInt8](repeating: 3, count: 32)), d1 = Hash32([UInt8](repeating: 4, count: 32))
        let stored = Self.load("relay.json")
        func wire<T>(_ key: String, _ make: () -> T, _ parse: ([UInt8]) throws -> T) -> T {
            if let hex = stored?[key] as? String, let bytes = [UInt8](hex: hex), let v = try? parse(bytes) { return v }
            return make()
        }
        // Three batches by the node; the receipt promises batch 2 after batch 1, and batch 2 lacks the item.
        let others = (0..<3).map { b in (0..<3).map { Hash32([UInt8](repeating: UInt8(0x40 + b * 4 + $0), count: 32)) } }
        let (batches, times, mmr) = Fixtures.commitments(node: node, batches: others)
        let checkpoint = Self.checkpoint(stored, "checkpoint_wire") { Fixtures.checkpoint(node: node, batches: batches, times: times) }
        let receipt = wire("receipt", { Receipt.sign(Receipt.Body(nodePk: node.publicKey, groupID: group, itemHash: item, contentDigest: d0, batchSeq: 2, batchPrev: batches[1].root, received: 10, deadline: 310, retainUntil: 7000), with: node) }, Receipt.fromWire)
        let request = wire("fetch", { FetchRequest.sign(FetchRequest.Body(requesterPk: member.publicKey, groupID: group, want: .item(item), nonce: [UInt8](repeating: 9, count: 16), time: 50), with: member) }, FetchRequest.fromWire)
        let notFound = wire("response_not_found", { FetchResponse.sign(FetchResponse.Body(nodePk: node.publicKey, requestHash: request.requestHash, status: .notFound, served: [], time: 60), with: node) }, FetchResponse.fromWire)
        let found = wire("response_found", { FetchResponse.sign(FetchResponse.Body(nodePk: node.publicKey, requestHash: request.requestHash, status: .found, served: [(item, d1)], time: 61), with: node) }, FetchResponse.fromWire)
        let early = wire("response_early", { FetchResponse.sign(FetchResponse.Body(nodePk: node.publicKey, requestHash: request.requestHash, status: .notFound, served: [], time: 5), with: node) }, FetchResponse.fromWire)
        let ackBody = Ack.Body(recipientPk: member.publicKey, nodePk: node.publicKey, groupID: group, itemHash: item, time: 70)
        let ack: Ack = (stored?["ack"] as? String).flatMap { [UInt8](hex: $0) }.map { Ack(body: ackBody, signature: Array($0.suffix(64))) } ?? Ack.sign(ackBody, with: member)
        #expect(receipt.isValid && request.isValid && notFound.isValid && found.isValid && ack.isValid)
        func bp(_ i: Int) -> BatchProof { BatchProof(root: batches[i].root, time: times[i], count: batches[i].count, proof: mmr.proof(index: i)!) }
        let (gi, _) = GapTree.gapLeaf(items: batches[2].leaves, around: item)!
        let f4 = FraudProof.f4(receipt: receipt, checkpoint: checkpoint, batch: bp(2), previous: bp(1), gap: GapProof(items: batches[2].leaves, index: gi))
        let f4Bad = FraudProof.f4(receipt: receipt, checkpoint: checkpoint, batch: bp(2), previous: bp(0), gap: GapProof(items: batches[2].leaves, index: gi))
        // F5: batch 0 logged with count 1 while its tree has three items.
        let shortEntry = LogEntry(root: batches[0].root, time: times[0], count: 1)
        let short = MMR(leaves: [shortEntry.leaf])
        let shortCheckpoint = Self.checkpoint(stored, "short_checkpoint_wire") {
            var c = WitnessedCheckpoint(checkpoint: Checkpoint.sign(log: short, entry: shortEntry, with: node))
            for w in Fixtures.witnessKeys { c.add(Cosignature.sign(c.checkpoint, time: times[0] + 1_000, with: w)) }
            return c
        }
        let f5 = FraudProof.f5(checkpoint: shortCheckpoint, batch: BatchProof(root: batches[0].root, time: times[0], count: 1, proof: short.proof(index: 0)!),
                               leaf: GapProof(items: batches[0].leaves, index: 3))
        let f5Bad = FraudProof.f5(checkpoint: shortCheckpoint, batch: BatchProof(root: batches[0].root, time: times[0], count: 1, proof: short.proof(index: 0)!),
                                  leaf: GapProof(items: batches[0].leaves, index: 1))
        // F6: a second checkpoint at the same seq over another history.
        var forkedEntries = Fixtures.entries(batches, times); forkedEntries[1].count += 1
        let forked = Checkpoint.sign(log: MMR(leaves: forkedEntries.map(\.leaf)), entry: forkedEntries.last!, with: node)
        let f6 = FraudProof.f6(first: checkpoint.checkpoint, second: forked, entries: [])
        let relay: [String: Any] = [
            "node_seed": node.seed.hex, "receipt": receipt.wire.hex, "fetch": request.wire.hex, "request_hash": request.requestHash.hex,
            "response_not_found": notFound.wire.hex, "response_found": found.wire.hex, "response_early": early.wire.hex,
            "ack": ack.wire.hex, "ack_leaf": ack.leaf.hex,
            "checkpoint_wire": checkpoint.wire.hex, "short_checkpoint_wire": shortCheckpoint.wire.hex,
            "log": ["size": Int(checkpoint.checkpoint.size), "peaks": checkpoint.checkpoint.mmrPeaks.map(\.hex)],
            "F1": FraudProof.f1(receipt: receipt, request: request, response: notFound, genesis: nil).verify() == .success(node.publicKey),
            "F1_negative_early": FraudProof.f1(receipt: receipt, request: request, response: early, genesis: nil).verify() == .failure(.outsideWindow),
            "F2": FraudProof.f2(first: notFound, second: found).verify() == .success(node.publicKey),
            "F2_negative": FraudProof.f2(first: notFound, second: notFound).verify() == .failure(.notAFraud),
            "F3": FraudProof.f3(receipt: receipt, response: found).verify() == .success(node.publicKey),
            "F3_negative": FraudProof.f3(receipt: receipt, response: notFound).verify() == .failure(.requestMismatch),
            "F4_wire": f4.wire.hex, "F4": f4.verify(witnessQuorum: 2) == .success(node.publicKey),
            "F4_negative": f4Bad.verify(witnessQuorum: 2) == .failure(.badProof),
            "F5_wire": f5.wire.hex, "F5": f5.verify(witnessQuorum: 2) == .success(node.publicKey),
            "F5_negative": f5Bad.verify(witnessQuorum: 2) == .failure(.notAFraud),
            "F6": f6.verify(witnessQuorum: 2) == .success(node.publicKey),
            "F6_negative": FraudProof.f6(first: checkpoint.checkpoint, second: checkpoint.checkpoint, entries: []).verify(witnessQuorum: 2) == .failure(.notAFraud),
        ]
        if let stored {
            var derived = relay
            for k in ["receipt", "fetch", "response_not_found", "response_found", "response_early", "ack", "F4_wire", "F5_wire"] { derived[k] = nil }
            Self.expectSame(derived, stored, file: "relay")
        } else { try Self.write("relay.json", relay) }

        // §11, §13.2, §24: what witnesses, identities and nodes sign.
        let witness = Fixtures.witnessKeys[0]
        let identity = try SigningKey(seed: Fixtures.seed(0x21))
        let entries = Fixtures.entries(batches, times)
        let witnessRequest = WitnessRequest(checkpoint: checkpoint.checkpoint, fromSeq: 1, entries: Array(entries.dropFirst()))
        let record = IdentityRecord(idPk: identity.publicKey, nodes: [NodeRef(nodePk: node.publicKey, url: "https://node.example")], updated: 1_700_000_000_000, signature: [UInt8](repeating: 0, count: 64))
        let descriptor = NodeDescriptor(nodePk: node.publicKey, operatorPk: identity.publicKey, url: "https://node.example", site: "europe-west1", turn: true,
                                        version: "2.0", time: 1_700_000_000_000, signature: [UInt8](repeating: 0, count: 64))
        try Self.check("witness.json", [
            "witness_seed": witness.seed.hex, "log_entries": entries.map { $0.borsh.hex }, "log_leaves": entries.map { $0.leaf.hex },
            "checkpoint_preimage": checkpoint.checkpoint.preimage.hex,
            "cosignature_preimage": Cosignature.preimage(checkpoint: checkpoint.checkpoint, time: times[2] + 1_000).hex,
            "witness_request_from_seq": Int(witnessRequest.fromSeq), "witness_request_entries": witnessRequest.entries.map { $0.borsh.hex },
            "identity_record_preimage": record.preimage.hex, "node_descriptor_preimage": descriptor.preimage.hex,
        ])

        var w = BorshWriter()
        w.vec([UInt8]()); w.option(Optional<UInt8>.none) { w, v in w.u8(v) }; w.option(1 as UInt8?) { w, v in w.u8(v) }
        let g = Fixtures.genesis(Fixtures.members(2))
        let big = Fixtures.message(g, author: 0, seq: 0, parents: [g.groupID], ts: 0, payload: [UInt8](repeating: 0xab, count: 65_536))
        try Self.check("borsh.json", ["edges": w.bytes.hex, "max_payload_message_hash": big.hash.hex, "max_payload_message_len": big.borsh.count])
    }

    /// §13.1 / A.6: a directory of 20 node keys, RV(group_id, 3) and RV(id_pk, 2).
    @Test func rendezvousVector() throws {
        let directory = (0..<20).map { Hash32([UInt8](repeating: UInt8(0x80 + $0), count: 32)) }
        let ms = Fixtures.members(3)
        let g = Fixtures.genesis(ms)
        try Self.check("rv.json", ["directory": directory.map(\.hex), "group_id": g.groupID.hex, "id_pk": ms[0].identity.publicKey.hex,
                                    "rv_group_3": Rendezvous.select(key: g.groupID, from: directory, count: 3).map(\.hex),
                                    "rv_id_2": Rendezvous.select(key: ms[0].identity.publicKey, from: directory, count: 2).map(\.hex),
                                    "rank_example": Rendezvous.rank(key: g.groupID, node: directory[0]).hex])
    }
}
