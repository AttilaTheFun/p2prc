import ConvoCore
import ConvoNet
import Foundation
import Testing

@Suite struct SyncTests {
    @Test func loopbackSyncFillsTheRequester() async throws {
        let ids = (0..<3).map { _ in SigningKey.random() }
        let salt = Hash32([UInt8](repeating: 5, count: 32))
        let gks = ids.map { $0.groupKey(salt: salt) }
        let d = Parameters.GenesisDefaults.forMembers(3)
        let g = Genesis(salt: salt, members: gks.map(\.publicKey), quorum: d.quorum, maxParents: 8, maxPayload: 4096, maxUncommittedRepublish: 10, homeNodes: [Hash32.zero])
        var holder = DAG(genesis: g)
        var parent = g.groupID
        var last = Hash32.zero
        for i in 0..<5 {
            let m = SignedMessage.sign(Message(groupID: g.groupID, authorIdx: UInt8(i % 3), seq: UInt64(i / 3), parents: [parent], ts: 0, kind: .chat, payload: [UInt8(i)]), with: gks[i % 3])
            last = try holder.insert(m); parent = last
        }
        let root = holder.contentRoot(under: last)
        _ = holder.record(SignedAttestation.sign(Attestation(groupID: g.groupID, head: last, contentRoot: root, msgCount: 5, signerIdx: 0), with: gks[0]))

        var requester = DAG(genesis: g)
        let (a, b) = LoopbackChannel.pair()
        let request = SyncRequest.sign(SyncRequest.Body(groupID: g.groupID, haveHead: .zero, wantHead: last, missing: nil, nonce: [UInt8](repeating: 0, count: 16), time: 1, requesterIdx: 1), with: gks[1])
        let served = holder
        let serving = Task { try await SyncResponder.serve(request, from: served, over: b) }
        let outcome = try await SyncClient.request(request, into: &requester, over: a)
        try await serving.value
        #expect(outcome.end == .complete && outcome.rejected == 0 && outcome.inserted.count == 5)
        #expect(requester.contentRoot(under: last) == root)
        #expect(requester.attestations(for: last).count == 1)
    }

    @Test func unauthorizedRequesterGetsNothing() async throws {
        let gk = SigningKey.random(); let other = SigningKey.random()
        let d = Parameters.GenesisDefaults.forMembers(1)
        let g = Genesis(salt: Hash32.zero, members: [gk.publicKey], quorum: d.quorum, maxParents: 8, maxPayload: 100, maxUncommittedRepublish: 10, homeNodes: [Hash32.zero])
        var holder = DAG(genesis: g)
        let m = SignedMessage.sign(Message(groupID: g.groupID, authorIdx: 0, seq: 0, parents: [g.groupID], ts: 0, kind: .chat, payload: []), with: gk)
        let head = try holder.insert(m)
        var requester = DAG(genesis: g)
        let (a, b) = LoopbackChannel.pair()
        let forged = SyncRequest.sign(SyncRequest.Body(groupID: g.groupID, haveHead: .zero, wantHead: head, missing: nil, nonce: [UInt8](repeating: 0, count: 16), time: 1, requesterIdx: 0), with: other)
        let served = holder
        let serving = Task { try await SyncResponder.serve(forged, from: served, over: b) }
        let outcome = try await SyncClient.request(forged, into: &requester, over: a)
        try await serving.value
        #expect(outcome.end == .unauthorized && outcome.inserted.isEmpty)
    }
}

@Suite struct HealthAndWireTests {
    @Test func healthDecaysAndFraudIsPermanent() {
        var h = NodeHealth()
        let n = Hash32([UInt8](repeating: 1, count: 32)), m = Hash32([UInt8](repeating: 2, count: 32))
        let t0 = Date(timeIntervalSince1970: 0)
        h.record(n, success: true, at: t0); h.record(n, success: true, at: t0)
        #expect(h.score(n, at: t0) == 2)
        #expect(abs(h.score(n, at: t0.addingTimeInterval(86_400)) - 1) < 1e-9)
        h.record(m, success: false, at: t0)
        #expect(h.pick(2, from: [m, n], at: t0) == [n, m])
        h.markFraudulent(m)
        #expect(h.pick(2, from: [m, n], at: t0) == [n])
    }

    @Test func hostHealthFollowsSection13() {
        var h = NodeHealth()
        let n = Hash32([UInt8](repeating: 1, count: 32))
        let t0 = Date(timeIntervalSince1970: 0)
        // Failing for less than HOST_UNHEALTHY_AFTER is a restart, not an outage.
        h.record(n, success: false, at: t0)
        h.record(n, success: false, at: t0.addingTimeInterval(300))
        #expect(h.isHealthy(n, at: t0.addingTimeInterval(300)))
        #expect(!h.isHealthy(n, at: t0.addingTimeInterval(600)))
        h.record(n, success: true, at: t0.addingTimeInterval(700))
        #expect(h.isHealthy(n, at: t0.addingTimeInterval(700)))
        // Two late fetch failures in a row.
        h.recordLateFetch(n, success: false, at: t0)
        #expect(h.isHealthy(n, at: t0))
        h.recordLateFetch(n, success: false, at: t0)
        #expect(!h.isHealthy(n, at: t0))
        h.recordLateFetch(n, success: true, at: t0)
        #expect(h.isHealthy(n, at: t0))
        h.markFraudulent(n)
        #expect(!h.isHealthy(n, at: t0))
    }

    @Test func fetchReplyRoundTrips() throws {
        let node = SigningKey.random()
        let response = FetchResponse.sign(FetchResponse.Body(nodePk: node.publicKey, requestHash: Hash32.zero, status: .found, served: [(Hash32.zero, Hashing.sha256([1, 2, 3]))], time: 5), with: node)
        let reply = FetchReply(response: response, items: [[1, 2, 3]])
        let back = try FetchReply.fromWire(reply.wire)
        #expect(back.items == [[1, 2, 3]] && back.response.body.served.count == 1 && back.response.isValid)
    }
}
