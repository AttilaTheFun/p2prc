import ConvoCore
import Foundation

/// Fixed seeds, so vectors are reproducible byte for byte.
enum Fixtures {
    static func seed(_ n: UInt8) -> [UInt8] { [UInt8](repeating: n, count: 32) }
    static let salt = Hash32([UInt8](repeating: 0x5a, count: 32))
    /// Three registered nodes' keys (§13.1), fixed like everything else here.
    static let nodeKeys = [0xa1, 0xa2, 0xa3].map { try! SigningKey(seed: seed(UInt8($0))) }
    static var homeNodes: [Hash32] { nodeKeys.map(\.publicKey) }

    struct Member {
        let identity: SigningKey
        let groupKey: SigningKey
    }

    static func members(_ count: Int, salt: Hash32 = salt) -> [Member] {
        (0..<count).map { i in
            let id = try! SigningKey(seed: seed(UInt8(i + 1)))
            return Member(identity: id, groupKey: id.groupKey(salt: salt))
        }
    }

    static func genesis(_ members: [Member], salt: Hash32 = salt, parent: ParentRef? = nil,
                        carry: [(UInt8, UInt8)] = [], reason: Genesis.Reason = .root) -> Genesis {
        let d = Parameters.GenesisDefaults.forMembers(members.count)
        return Genesis(salt: salt, members: members.map(\.groupKey.publicKey), quorum: d.quorum,
                       maxParents: d.maxParents, maxPayload: d.maxPayload, maxUncommittedRepublish: d.maxUncommittedRepublish, homeNodes: homeNodes,
                       parent: parent, carry: carry, reason: reason)
    }

    static func message(_ genesis: Genesis, author: Int, seq: UInt64, parents: [Hash32], ts: UInt64,
                        kind: Message.Kind = .chat, payload: [UInt8]) -> Message {
        Message(groupID: genesis.groupID, authorIdx: UInt8(author), seq: seq, parents: parents, ts: ts, kind: kind, payload: payload)
    }

    /// Three members, three messages (two concurrent) and the head joining them: the vectors' shape.
    static func sampleDAG() -> (members: [Member], genesis: Genesis, dag: DAG, signed: [SignedMessage]) {
        let ms = members(3)
        let g = genesis(ms)
        var dag = DAG(genesis: g)
        let m1 = SignedMessage.sign(message(g, author: 0, seq: 0, parents: [g.groupID], ts: 1_700_000_000_000, payload: Array("hello".utf8)), with: ms[0].groupKey)
        try! dag.insert(m1)
        let m2 = SignedMessage.sign(message(g, author: 1, seq: 0, parents: [m1.hash], ts: 1_700_000_001_000, payload: Array("hi".utf8)), with: ms[1].groupKey)
        let m3 = SignedMessage.sign(message(g, author: 2, seq: 0, parents: [m1.hash], ts: 1_700_000_001_000, payload: Array("hey".utf8)), with: ms[2].groupKey)
        try! dag.insert(m2); try! dag.insert(m3)
        let m4 = SignedMessage.sign(message(g, author: 0, seq: 1, parents: [m2.hash, m3.hash], ts: 1_700_000_002_000, payload: Array("all".utf8)), with: ms[0].groupKey)
        try! dag.insert(m4)
        return (ms, g, dag, [m1, m2, m3, m4])
    }

    /// Two witnesses, independent of every fixture node.
    static let witnessKeys = [0xb1, 0xb2].map { try! SigningKey(seed: seed(UInt8($0))) }

    /// A node's log after `batches` batches, each committing the given
    /// items, closed five minutes apart; returns the batches, their times
    /// and the accumulator.
    static func commitments(node: SigningKey, batches items: [[Hash32]]) -> (batches: [CommitmentBatch], times: [UInt64], mmr: MMR) {
        var mmr = MMR()
        var out: [CommitmentBatch] = []
        var times: [UInt64] = []
        var prev = Hash32.zero
        for (i, leaves) in items.enumerated() {
            let b = CommitmentBatch.sign(nodePk: node.publicKey, seq: UInt64(i), prevRoot: prev, leaves: leaves, with: node)
            let time = 1_700_000_000_000 + 300_000 * UInt64(i)
            mmr.append(MMR.leaf(root: b.root, time: time, count: b.count))
            out.append(b); times.append(time); prev = b.root
        }
        return (out, times, mmr)
    }

    /// The log's entries.
    static func entries(_ batches: [CommitmentBatch], _ times: [UInt64]) -> [LogEntry] {
        zip(batches, times).map { LogEntry(root: $0.root, time: $1, count: $0.count) }
    }

    /// A checkpoint of the log after its last batch, cosigned by `witnesses`.
    static func checkpoint(node: SigningKey, batches: [CommitmentBatch], times: [UInt64], witnesses: [SigningKey] = witnessKeys) -> WitnessedCheckpoint {
        let entries = entries(batches, times)
        let checkpoint = Checkpoint.sign(log: MMR(leaves: entries.map(\.leaf)), entry: entries.last!, with: node)
        var witnessed = WitnessedCheckpoint(checkpoint: checkpoint)
        for w in witnesses { witnessed.add(Cosignature.sign(checkpoint, time: checkpoint.time + 1_000, with: w)) }
        return witnessed
    }
}
