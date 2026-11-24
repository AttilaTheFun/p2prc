import ConvoCore
import Foundation
import Testing

@Suite struct BorshTests {
    @Test func roundTripsEveryShape() throws {
        var w = BorshWriter()
        w.u8(7); w.u16(0x1234); w.u32(0xdead_beef); w.u64(1 << 40); w.bool(true); w.vec([1, 2, 3]); w.string("héllo")
        w.option(Optional<UInt8>.none) { w, v in w.u8(v) }; w.option(9 as UInt8?) { w, v in w.u8(v) }
        var r = BorshReader(w.bytes)
        #expect(try r.u8() == 7); #expect(try r.u16() == 0x1234); #expect(try r.u32() == 0xdead_beef); #expect(try r.u64() == 1 << 40)
        #expect(try r.bool() == true); #expect(try r.vec() == [1, 2, 3]); #expect(try r.string() == "héllo")
        #expect(try r.option { try $0.u8() } == nil); #expect(try r.option { try $0.u8() } == 9)
        try r.finish()
    }

    @Test func littleEndianAndLengthPrefix() {
        var w = BorshWriter(); w.u32(1); w.vec([0xaa])
        #expect(w.bytes == [1, 0, 0, 0, 1, 0, 0, 0, 0xaa])
    }

    @Test func rejectsTrailingBytes() {
        var r = BorshReader([1, 2])
        _ = try? r.u8()
        #expect(throws: BorshError.self) { try r.finish() }
    }
}

@Suite struct IdentityTests {
    @Test func recoveryPhraseKnownSeed() throws {
        let words = Array(repeating: "abandon", count: 11) + ["about"]
        #expect(try Mnemonic.entropy(from: words) == [UInt8](repeating: 0, count: 16))
        #expect(try Mnemonic.phrase(from: [UInt8](repeating: 0, count: 16)) == words)
        // The Trezor vector for this phrase with the passphrase "TREZOR".
        #expect(Mnemonic.seed(words: words, passphrase: "TREZOR").hex == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
        #expect(throws: Mnemonic.Failure.badChecksum) { try Mnemonic.entropy(from: Array(repeating: "abandon", count: 12)) }
        let fresh = Mnemonic.generate()
        #expect(fresh.count == 12 && (try? Mnemonic.entropy(from: fresh)) != nil)
    }

    @Test func identityIsStableAndImportsSecretKeys() throws {
        let words = Mnemonic.generate()
        let a = try IdentityKey.key(words: words), b = try IdentityKey.key(words: words)
        #expect(a.publicKey == b.publicKey)
        #expect(try IdentityKey.key(words: words, passphrase: "x").publicKey != a.publicKey)
        let exported = a.seed + a.publicKey.bytes
        #expect(try IdentityKey.key(secretKey: exported).publicKey == a.publicKey)
        #expect(try IdentityKey.key(secretKey: a.seed).publicKey == a.publicKey)
        #expect(throws: (any Error).self) { try IdentityKey.key(secretKey: a.seed + [UInt8](repeating: 1, count: 32)) }
        #expect(a.hpkeSeed(index: 0) != a.hpkeSeed(index: 1))
        #expect(a.groupKey(salt: Fixtures.salt).publicKey != a.publicKey)
    }
}

@Suite struct MerkleTests {
    @Test func emptyRootIsTaggedLeafHash() { #expect(Merkle.root(leaves: []) == Hashing.hash("convo/leaf")) }

    @Test func oddLevelsPromoteAndProofsVerify() {
        let leaves = (0..<5).map { Hash32([UInt8](repeating: UInt8($0), count: 32)) }
        let root = Merkle.root(leaves: leaves)
        for i in leaves.indices {
            #expect(Merkle.verify(leaf: leaves[i], proof: Merkle.proof(leaves: leaves, index: i), root: root))
        }
        #expect(!Merkle.verify(leaf: leaves[0], proof: Merkle.proof(leaves: leaves, index: 1), root: root))
        #expect(Merkle.verify(leaf: leaves[4], proof: Merkle.proof(leaves: leaves, index: 4), root: root))
        #expect(Merkle.impliedIndex(of: Merkle.proof(leaves: leaves, index: 3)) == 3)
        for i in leaves.indices {
            #expect(Merkle.verify(leaf: leaves[i], proof: Merkle.proof(leaves: leaves, index: i), root: root, index: i, count: 5))
            #expect(!Merkle.verify(leaf: leaves[i], proof: Merkle.proof(leaves: leaves, index: i), root: root, index: (i + 1) % 5, count: 5))
        }
    }
}

@Suite struct CommitmentTests {
    @Test func gapTreeProvesMembershipAndAbsence() {
        let items = [5, 1, 3, 3, 9].map { Hash32([UInt8](repeating: UInt8($0), count: 32)) }
        let leaves = GapTree.leaves(items: items)
        #expect(leaves.count == 5 && leaves.first?.lo == GapTree.low && leaves.last?.hi == GapTree.high)
        let root = GapTree.root(items: items)
        let three = Hash32([UInt8](repeating: 3, count: 32)), four = Hash32([UInt8](repeating: 4, count: 32))
        let (i, leaf) = GapTree.membershipLeaf(items: items, item: three)!
        #expect(GapTree.verifyMembership(item: three, leaf: leaf, proof: GapTree.proof(items: items, leafIndex: i), root: root))
        let (j, gap) = GapTree.gapLeaf(items: items, around: four)!
        #expect(gap.lo == three && GapTree.verifyNonMembership(item: four, leaf: gap, proof: GapTree.proof(items: items, leafIndex: j), root: root))
        #expect(!GapTree.verifyNonMembership(item: three, leaf: gap, proof: GapTree.proof(items: items, leafIndex: j), root: root))
        #expect(GapTree.gapLeaf(items: items, around: three) == nil)
        // The boundary sentinels prove absence below and above everything.
        let low = GapTree.gapLeaf(items: items, around: Hash32([UInt8](repeating: 0, count: 31) + [1]))!
        #expect(low.leaf.lo == GapTree.low && GapTree.verify(leaf: low.leaf, proof: GapTree.proof(items: items, leafIndex: low.index), root: root))
        #expect(GapTree.root(items: []) == Hashing.hash("convo/gnode", GapTree.Leaf(lo: GapTree.low, hi: GapTree.high).hash.bytes) || GapTree.root(items: []) == GapTree.Leaf(lo: GapTree.low, hi: GapTree.high).hash)
    }

    @Test func mmrPeaksAndProofs() {
        var mmr = MMR()
        let leaves = (0..<8).map { Hash32([UInt8](repeating: UInt8(0x10 + $0), count: 32)) }
        for (n, leaf) in leaves.enumerated() {
            mmr.append(leaf)
            #expect(mmr.peaks.count == (n + 1).nonzeroBitCount)
            for i in 0...n {
                let proof = mmr.proof(index: i)!
                #expect(MMR.verify(leaf: leaves[i], proof: proof, peaks: mmr.peaks, size: mmr.size) == i)
            }
        }
        // A leaf under the wrong peak, a wrong size, and a tampered sibling all fail.
        let proof = mmr.proof(index: 5)!
        #expect(MMR.verify(leaf: leaves[5], proof: proof, peaks: mmr.peaks, size: 7) == nil)
        #expect(MMR.verify(leaf: leaves[4], proof: proof, peaks: mmr.peaks, size: 8) == nil)
        var bad = proof; bad.siblings[0] = Merkle.ProofStep(sibling: leaves[0], side: bad.siblings[0].side)
        #expect(MMR.verify(leaf: leaves[5], proof: bad, peaks: mmr.peaks, size: 8) == nil)
    }

    @Test func batchesSignAndReferencesResolve() throws {
        let node = Fixtures.nodeKeys[0]
        let items = (0..<3).map { b in (0..<4).map { Hash32([UInt8](repeating: UInt8(b * 16 + $0 + 1), count: 32)) } }
        let (batches, times, mmr) = Fixtures.commitments(node: node, batches: items)
        let checkpoint = Fixtures.checkpoint(node: node, batches: batches, times: times)
        for b in batches { #expect(b.isValid); let d = try CommitmentBatch.fromWire(b.wire); #expect(d == b) }
        let item = items[1][2]
        let ref = batches[1].reference(item: item, time: times[1], mmr: mmr, checkpoint: checkpoint)!
        #expect(ref.resolves())
        let decodedRef = try CommitmentRef.decode(ref.borsh)
        #expect(decodedRef == ref)
        var tampered = ref; tampered.itemHash = items[2][0]
        #expect(!tampered.resolves())
        var wrongBatch = ref; wrongBatch.batchSeq = 2
        #expect(!wrongBatch.resolves())
        #expect(batches[1].reference(item: items[2][0], time: times[1], mmr: mmr, checkpoint: checkpoint) == nil)
        // One witness is not a quorum; the node can't witness itself.
        let thin = Fixtures.checkpoint(node: node, batches: batches, times: times, witnesses: [Fixtures.witnessKeys[0], node])
        #expect(!batches[1].reference(item: item, time: times[1], mmr: mmr, checkpoint: thin)!.resolves())
        // A ref made against an earlier checkpoint still resolves against its own.
        let early = Fixtures.checkpoint(node: node, batches: Array(batches.prefix(2)), times: Array(times.prefix(2)))
        #expect(batches[1].reference(item: item, time: times[1], mmr: mmr, checkpoint: early)!.resolves())
        #expect(batches[2].reference(item: items[2][0], time: times[2], mmr: mmr, checkpoint: early) == nil)
    }
}

@Suite struct DAGTests {
    @Test func canonicalOrderBreaksTiesBySmallestHash() {
        let s = Fixtures.sampleDAG()
        let order = s.dag.canonicalOrder(under: s.signed[3].hash)
        #expect(order.first == s.signed[0].hash && order.last == s.signed[3].hash)
        let middle = [s.signed[1].hash, s.signed[2].hash].sorted()
        #expect(Array(order[1...2]) == middle)
    }

    @Test func contentRootHasInclusionProofs() {
        let s = Fixtures.sampleDAG()
        let head = s.signed[3].hash
        let root = s.dag.contentRoot(under: head)
        for m in s.signed { #expect(Merkle.verify(leaf: m.leaf, proof: s.dag.inclusionProof(of: m.hash, under: head)!, root: root)) }
    }

    @Test func insertRejectsWhatItCanCheck() throws {
        let ms = Fixtures.members(2)
        let g = Fixtures.genesis(ms)
        var dag = DAG(genesis: g)
        let ok = SignedMessage.sign(Fixtures.message(g, author: 0, seq: 0, parents: [g.groupID], ts: 0, payload: [1]), with: ms[0].groupKey)
        try dag.insert(ok)
        func failure(_ m: SignedMessage) -> DAG.InsertError? {
            do { try dag.insert(m) } catch let e as DAG.InsertError { return e } catch { return nil }
            return nil
        }
        #expect(failure(ok) == .duplicate)
        let wrongKey = SignedMessage.sign(Fixtures.message(g, author: 1, seq: 0, parents: [ok.hash], ts: 0, payload: [1]), with: ms[0].groupKey)
        #expect(failure(wrongKey) == .badSignature)
        let orphan = SignedMessage.sign(Fixtures.message(g, author: 1, seq: 0, parents: [Hash32.zero], ts: 0, payload: [1]), with: ms[1].groupKey)
        #expect(failure(orphan) == .unknownParent(Hash32.zero))
        let big = SignedMessage.sign(Fixtures.message(g, author: 1, seq: 0, parents: [ok.hash], ts: 0, payload: [UInt8](repeating: 0, count: 65_537)), with: ms[1].groupKey)
        #expect(failure(big) == .payloadTooLarge)
    }

    @Test func republishCapIsPerAuthorOverTheUncommittedRange() throws {
        let ms = Fixtures.members(2)
        let g = Fixtures.genesis(ms)
        var dag = DAG(genesis: g)
        var parent = g.groupID
        for i in 0..<11 {
            let m = SignedMessage.sign(Fixtures.message(g, author: 0, seq: UInt64(i), parents: [parent], ts: 0, kind: .republish, payload: [1]), with: ms[0].groupKey)
            try dag.insert(m); parent = m.hash
        }
        #expect(dag.validate(head: parent) == .republishCapExceeded(authorIdx: 0, count: 11))
        // Once committed, republishes stop counting against the cap.
        for h in dag.canonicalOrder(under: parent).prefix(3) { dag.markCommitted(h) }
        #expect(dag.validate(head: parent) == nil)
    }

    @Test func statesFollowAttestationsAndCommitments() throws {
        let s = Fixtures.sampleDAG()
        var dag = s.dag
        let head = s.signed[3].hash
        #expect(dag.state(of: s.signed[0].hash) == .sent)
        let root = dag.contentRoot(under: head)
        let a1 = SignedAttestation.sign(Attestation(groupID: s.genesis.groupID, head: head, contentRoot: root, msgCount: 4, signerIdx: 1), with: s.members[1].groupKey)
        let r1 = dag.record(a1)
        #expect(r1)
        let wrongRoot = SignedAttestation.sign(Attestation(groupID: s.genesis.groupID, head: head, contentRoot: Hash32.zero, msgCount: 4, signerIdx: 2), with: s.members[2].groupKey)
        let rw = dag.record(wrongRoot)
        #expect(!rw)
        #expect(dag.state(of: s.signed[0].hash) == .sent)   // quorum for 3 is 2
        let a2 = SignedAttestation.sign(Attestation(groupID: s.genesis.groupID, head: head, contentRoot: root, msgCount: 4, signerIdx: 2), with: s.members[2].groupKey)
        let r2 = dag.record(a2)
        #expect(r2)
        #expect(dag.state(of: s.signed[0].hash) == .attested)   // transitively, from the head
        dag.markCommitted(s.signed[0].hash)
        #expect(dag.state(of: s.signed[0].hash) == .committed)
        #expect(dag.uncommitted(under: head).count == 3)
    }
}

@Suite struct ForkTests {
    @Test func officialNeedsCarryThreshold() {
        let ms = Fixtures.members(3)
        let g = Fixtures.genesis(ms)
        let node = Fixtures.nodeKeys[0]
        let att = Attestation(groupID: g.groupID, head: Hash32([UInt8](repeating: 0x33, count: 32)), contentRoot: Hash32.zero, msgCount: 1, signerIdx: 0)
        let (batches, times, mmr) = Fixtures.commitments(node: node, batches: [[att.itemHash]])
        let checkpoint = Fixtures.checkpoint(node: node, batches: batches, times: times)
        let ref = ParentRef(groupID: g.groupID, head: att.head, source: batches[0].reference(item: att.itemHash, time: times[0], mmr: mmr, checkpoint: checkpoint)!)
        let childSalt = Hash32([UInt8](repeating: 0x7c, count: 32))
        let childMembers = [0, 1].map { i in Fixtures.Member(identity: ms[i].identity, groupKey: ms[i].identity.groupKey(salt: childSalt)) }
        let child = Fixtures.genesis(childMembers, salt: childSalt, parent: ref, carry: [(0, 0), (1, 1)], reason: .membership)
        let hash = ForkAuthorization.preimage(parent: g.groupID, child: child.groupID)
        #expect(ForkAuthorization.threshold(parentQuorum: g.quorum, carryCount: 2) == 2)
        let one = [(UInt8(0), ms[0].groupKey.sign(hash))]
        #expect(!ForkAuthorization.isOfficial(child: child, parentQuorum: g.quorum, parentMembers: g.members, carrySigs: one))
        let both = one + [(UInt8(1), ms[1].groupKey.sign(hash))]
        #expect(ForkAuthorization.isOfficial(child: child, parentQuorum: g.quorum, parentMembers: g.members, carrySigs: both))
        // A signature from a parent member not in `carry` does not count.
        let stranger = [(UInt8(2), ms[2].groupKey.sign(hash))]
        #expect(ForkAuthorization.verify(child: child, parentMembers: g.members, carrySigs: stranger).isEmpty)
        #expect(try! Genesis.decode(child.borsh) == child)
    }

    @Test func republishVerifiesThroughACommittedAttestation() {
        let s = Fixtures.sampleDAG()
        let head = s.signed[3].hash
        let att = SignedAttestation.sign(Attestation(groupID: s.genesis.groupID, head: head, contentRoot: s.dag.contentRoot(under: head), msgCount: 4, signerIdx: 0), with: s.members[0].groupKey)
        let node = Fixtures.nodeKeys[1]
        let (batches, times, mmr) = Fixtures.commitments(node: node, batches: [[s.signed[0].hash], [att.itemHash, s.signed[3].hash]])
        let checkpoint = Fixtures.checkpoint(node: node, batches: batches, times: times)
        let source = batches[1].reference(item: att.itemHash, time: times[1], mmr: mmr, checkpoint: checkpoint)!
        let rp = Republish(parentGroupID: s.genesis.groupID, source: source, attestation: att, original: s.signed[1], inclusionProof: s.dag.inclusionProof(of: s.signed[1].hash, under: head)!)
        #expect(rp.verify(parentMembers: s.genesis.members))
        #expect(try! Republish.decode(rp.borsh) == rp)
        var forged = rp; forged.original.ts += 1
        #expect(!forged.verify(parentMembers: s.genesis.members))
        // An unwitnessed source does not resolve.
        var unwitnessed = rp; unwitnessed.source.checkpoint.cosignatures = []
        #expect(!unwitnessed.verify(parentMembers: s.genesis.members))
    }
}

@Suite struct RelayTests {
    let node = try! SigningKey(seed: Fixtures.seed(0x77))
    let member = Fixtures.members(1)[0].groupKey
    let group = Hash32([UInt8](repeating: 1, count: 32)), item = Hash32([UInt8](repeating: 2, count: 32))
    let d0 = Hash32([UInt8](repeating: 3, count: 32)), d1 = Hash32([UInt8](repeating: 4, count: 32))

    func receipt(batchSeq: UInt64 = 3, batchPrev: Hash32 = Hash32([UInt8](repeating: 8, count: 32))) -> Receipt {
        Receipt.sign(Receipt.Body(nodePk: node.publicKey, groupID: group, itemHash: item, contentDigest: d0, batchSeq: batchSeq, batchPrev: batchPrev,
                                  received: 10, deadline: 310, retainUntil: 7000), with: node)
    }
    func request() -> FetchRequest {
        FetchRequest.sign(FetchRequest.Body(requesterPk: member.publicKey, groupID: group, want: .item(item), nonce: [UInt8](repeating: 9, count: 16), time: 50), with: member)
    }
    func response(_ status: FetchStatus, served: [(Hash32, Hash32)], time: UInt64 = 60) -> FetchResponse {
        FetchResponse.sign(FetchResponse.Body(nodePk: node.publicKey, requestHash: request().requestHash, status: status, served: served, time: time), with: node)
    }

    @Test func receiptsAndRequestsRoundTripAndVerify() throws {
        let r = receipt()
        #expect(r.isValid && r.wire.count == Receipt.wireCount)
        let decoded = try Receipt.fromWire(r.wire)
        #expect(decoded == r)
        let req = request(), decodedReq = try FetchRequest.fromWire(req.wire)
        #expect(req.isValid && decodedReq == req)
    }

    @Test func f1DeniedCustodyInsideTheWindow() {
        #expect(FraudProof.f1(receipt: receipt(), request: request(), response: response(.notFound, served: []), genesis: nil).verify() == .success(node.publicKey))
        #expect(FraudProof.f1(receipt: receipt(), request: request(), response: response(.found, served: [(item, d0)]), genesis: nil).verify() == .failure(.notAFraud))
        #expect(FraudProof.f1(receipt: receipt(), request: request(), response: response(.notFound, served: [], time: 7001), genesis: nil).verify() == .failure(.outsideWindow))
        #expect(FraudProof.f1(receipt: receipt(), request: request(), response: response(.notFound, served: [], time: 9), genesis: nil).verify() == .failure(.outsideWindow))
        // `unauthorized` is a fraud only with the genesis showing the requester is a member.
        let denied = response(.unauthorized, served: [])
        #expect(FraudProof.f1(receipt: receipt(), request: request(), response: denied, genesis: nil).verify() == .failure(.unauthorizedNeedsGenesis))
        let g = Genesis(salt: Fixtures.salt, members: [member.publicKey], quorum: 1, maxParents: 8, maxPayload: 1, maxUncommittedRepublish: 1, homeNodes: [node.publicKey])
        let rcpt = Receipt.sign(Receipt.Body(nodePk: node.publicKey, groupID: g.groupID, itemHash: item, contentDigest: d0, batchSeq: 0, batchPrev: .zero, received: 10, deadline: 310, retainUntil: 7000), with: node)
        let req = FetchRequest.sign(FetchRequest.Body(requesterPk: member.publicKey, groupID: g.groupID, want: .item(item), nonce: [UInt8](repeating: 9, count: 16), time: 50), with: member)
        let resp = FetchResponse.sign(FetchResponse.Body(nodePk: node.publicKey, requestHash: req.requestHash, status: .unauthorized, served: [], time: 60), with: node)
        #expect(FraudProof.f1(receipt: rcpt, request: req, response: resp, genesis: g.borsh).verify() == .success(node.publicKey))
    }

    @Test func f2Equivocation() {
        let a = response(.notFound, served: []), b = response(.found, served: [(item, d0)])
        #expect(FraudProof.f2(first: a, second: b).verify() == .success(node.publicKey))
        #expect(FraudProof.f2(first: a, second: a).verify() == .failure(.notAFraud))
    }

    @Test func f3DifferentBytes() {
        #expect(FraudProof.f3(receipt: receipt(), response: response(.found, served: [(item, d1)])).verify() == .success(node.publicKey))
        #expect(FraudProof.f3(receipt: receipt(), response: response(.found, served: [(item, d0)])).verify() == .failure(.notAFraud))
    }

    @Test func f4OmittedFromThePromisedBatch() throws {
        // Batches 0..2; the receipt promises batch 2 after batch 1's root, and batch 2 lacks the item.
        let others = (0..<3).map { b in (0..<3).map { Hash32([UInt8](repeating: UInt8(0x40 + b * 4 + $0), count: 32)) } }
        let (batches, times, mmr) = Fixtures.commitments(node: node, batches: others)
        let checkpoint = Fixtures.checkpoint(node: node, batches: batches, times: times)
        let r = receipt(batchSeq: 2, batchPrev: batches[1].root)
        func batchProof(_ i: Int) -> BatchProof { BatchProof(root: batches[i].root, time: times[i], count: batches[i].count, proof: mmr.proof(index: i)!) }
        let (gi, _) = GapTree.gapLeaf(items: batches[2].leaves, around: item)!
        let gapProof = GapProof(items: batches[2].leaves, index: gi)
        let f4 = FraudProof.f4(receipt: r, checkpoint: checkpoint, batch: batchProof(2), previous: batchProof(1), gap: gapProof)
        #expect(f4.verify() == .success(node.publicKey))
        let decodedF4 = try FraudProof.fromWire(f4.wire)
        #expect(decodedF4 == f4)
        // Unwitnessed, the batch isn't published yet: no fraud.
        let bare = WitnessedCheckpoint(checkpoint: checkpoint.checkpoint)
        #expect(FraudProof.f4(receipt: r, checkpoint: bare, batch: batchProof(2), previous: batchProof(1), gap: gapProof).verify() == .failure(.unwitnessed))
        // Wrong previous root: the receipt was about some other sequence.
        let stale = receipt(batchSeq: 2, batchPrev: batches[0].root)
        #expect(FraudProof.f4(receipt: stale, checkpoint: checkpoint, batch: batchProof(2), previous: batchProof(1), gap: gapProof).verify() == .failure(.badProof))
        // A batch that does contain the item is not a fraud.
        let (withItem, times2, mmr2) = Fixtures.commitments(node: node, batches: [others[0], others[1], others[2] + [item]])
        let checkpoint2 = Fixtures.checkpoint(node: node, batches: withItem, times: times2)
        let r2 = receipt(batchSeq: 2, batchPrev: withItem[1].root)
        #expect(GapTree.gapLeaf(items: withItem[2].leaves, around: item) == nil)
        let bp2 = BatchProof(root: withItem[2].root, time: times2[2], count: withItem[2].count, proof: mmr2.proof(index: 2)!)
        let bp1 = BatchProof(root: withItem[1].root, time: times2[1], count: withItem[1].count, proof: mmr2.proof(index: 1)!)
        #expect(FraudProof.f4(receipt: r2, checkpoint: checkpoint2, batch: bp2, previous: bp1, gap: gapProof).verify() == .failure(.notAFraud))
    }

    @Test func f5UnderstatedCount() {
        // The node logs count 2 for a batch whose tree has 5 items (6 gap leaves).
        let items = (0..<5).map { Hash32([UInt8](repeating: UInt8(0x60 + $0), count: 32)) }
        let batch = CommitmentBatch.sign(nodePk: node.publicKey, seq: 0, prevRoot: .zero, leaves: items, with: node)
        let entry = LogEntry(root: batch.root, time: 100, count: 2)
        let mmr = MMR(leaves: [entry.leaf])
        var checkpoint = WitnessedCheckpoint(checkpoint: Checkpoint.sign(log: mmr, entry: entry, with: node))
        for w in Fixtures.witnessKeys { checkpoint.add(Cosignature.sign(checkpoint.checkpoint, time: 200, with: w)) }
        let proof = BatchProof(root: batch.root, time: 100, count: 2, proof: mmr.proof(index: 0)!)
        for i in 3...5 {
            #expect(FraudProof.f5(checkpoint: checkpoint, batch: proof, leaf: GapProof(items: items, index: i)).verify() == .success(node.publicKey))
        }
        #expect(FraudProof.f5(checkpoint: checkpoint, batch: proof, leaf: GapProof(items: items, index: 1)).verify() == .failure(.notAFraud))
        // Claiming a higher index for a real leaf's path does not verify.
        var lied = GapProof(items: items, index: 1); lied.index = 4
        #expect(FraudProof.f5(checkpoint: checkpoint, batch: proof, leaf: lied).verify() == .failure(.badProof))
    }

    @Test func acksVerify() throws {
        let ack = Ack.sign(Ack.Body(recipientPk: member.publicKey, nodePk: node.publicKey, groupID: group, itemHash: item, time: 70), with: member)
        let decodedAck = try Ack.fromWire(ack.wire)
        #expect(ack.isValid && decodedAck == ack)
    }
}

@Suite struct WitnessTests {
    let node = try! SigningKey(seed: Fixtures.seed(0x77))
    let witness = Fixtures.witnessKeys[0]

    func log(_ n: Int) -> (batches: [CommitmentBatch], times: [UInt64], entries: [LogEntry]) {
        let items = (0..<n).map { b in [Hash32([UInt8](repeating: UInt8(0x10 + b), count: 32))] }
        let (batches, times, _) = Fixtures.commitments(node: node, batches: items)
        return (batches, times, Fixtures.entries(batches, times))
    }

    func checkpoint(_ entries: [LogEntry]) -> Checkpoint {
        Checkpoint.sign(log: MMR(leaves: entries.map(\.leaf)), entry: entries.last!, with: node)
    }

    @Test func witnessCosignsAnHonestlyExtendedLog() throws {
        let (_, times, entries) = log(3)
        var copy = LogWitness(nodePk: node.publicKey)
        let first = checkpoint(Array(entries.prefix(2)))
        guard case .cosign(let c1) = copy.witness(WitnessRequest(checkpoint: first, fromSeq: 0, entries: Array(entries.prefix(2))), now: times[1], with: witness) else {
            Issue.record("first checkpoint refused"); return
        }
        #expect(c1.verifies(first) && copy.size == 2)
        let second = checkpoint(entries)
        // Sent from the wrong place: the witness says where to resume.
        #expect(copy.witness(WitnessRequest(checkpoint: second, fromSeq: 0, entries: entries), now: times[2], with: witness) == .resendFrom(size: 2))
        guard case .cosign = copy.witness(WitnessRequest(checkpoint: second, fromSeq: 2, entries: [entries[2]]), now: times[2], with: witness) else {
            Issue.record("extension refused"); return
        }
        #expect(copy.latest?.checkpoint == second)
        let request = WitnessRequest(checkpoint: second, fromSeq: 2, entries: [entries[2]])
        #expect(try WitnessRequest.fromWire(request.wire) == request)
        // Too far from the witness's clock.
        var fresh = LogWitness(nodePk: node.publicKey)
        guard case .rejected = fresh.witness(WitnessRequest(checkpoint: first, fromSeq: 0, entries: Array(entries.prefix(2))),
                                             now: times[1] + Parameters.Node.witnessSkewMs + 1, with: witness) else {
            Issue.record("skewed checkpoint cosigned"); return
        }
    }

    @Test func aRewrittenHistoryIsF6() throws {
        let (_, times, entries) = log(3)
        var copy = LogWitness(nodePk: node.publicKey)
        let honest = checkpoint(entries)
        _ = copy.witness(WitnessRequest(checkpoint: honest, fromSeq: 0, entries: entries), now: times[2], with: witness)
        // The same seq, another history.
        var rewritten = entries; rewritten[1] = LogEntry(root: Hash32([UInt8](repeating: 0xee, count: 32)), time: entries[1].time, count: 1)
        let other = checkpoint(rewritten)
        #expect(copy.witness(WitnessRequest(checkpoint: other, fromSeq: 3, entries: []), now: times[2], with: witness) == .conflict(earlier: honest))
        #expect(Checkpoint.equivocate(honest, other))
        let f6 = FraudProof.f6(first: honest, second: other, entries: [])
        #expect(f6.verify() == .success(node.publicKey))
        #expect(try FraudProof.fromWire(f6.wire) == f6)
        // A later checkpoint whose log doesn't contain the earlier one.
        let early = checkpoint(Array(entries.prefix(2)))
        let extended = rewritten + [LogEntry(root: Hash32([UInt8](repeating: 0xef, count: 32)), time: times[2] + 1, count: 1)]
        let later = checkpoint(extended)
        #expect(FraudProof.f6(first: early, second: later, entries: extended).verify() == .success(node.publicKey))
        // An honest extension is not.
        #expect(FraudProof.f6(first: early, second: honest, entries: entries).verify() == .failure(.notAFraud))
    }

    @Test func identityRecordsAndDescriptorsVerify() throws {
        let identity = try SigningKey(seed: Fixtures.seed(0x21))
        let record = IdentityRecord.sign(nodes: [NodeRef(nodePk: node.publicKey, url: "https://node.example")], updated: 5, with: identity)
        #expect(record.isValid)
        #expect(try IdentityRecord.fromWire(record.wire) == record)
        var forged = record; forged.updated = 6
        #expect(!forged.isValid)
        #expect(!IdentityRecord.sign(nodes: [], updated: 5, with: identity).isValid)
        let descriptor = NodeDescriptor.sign(operatorPk: identity.publicKey, url: "https://node.example", site: "europe-west1", turn: true,
                                             version: "2.0", time: 7, with: node)
        #expect(descriptor.isValid)
        #expect(try NodeDescriptor.decode(descriptor.borsh) == descriptor)
        var moved = descriptor; moved.url = "https://elsewhere.example"
        #expect(!moved.isValid)
    }
}

/// A vector length above what is left (and above a 32-bit Int) is a thrown
/// error, never a trap: every fetched item is tried as a message first.
@Test func borshGarbageLengthThrows() {
    var r = BorshReader([0xff, 0xff, 0xff, 0xff, 1, 2, 3])
    #expect(throws: BorshError.self) { try r.vec() }
    var r2 = BorshReader([0xff, 0xff, 0xff, 0x7f])
    #expect(throws: BorshError.self) { try r2.vec { try $0.u8() } }
}
