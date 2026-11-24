import ConvoCore
import ConvoSession
import ConvoMLS
import Foundation

/// On-disk state for a client: the identity secret, and per group the
/// genesis, roster, MLS secrets, every message and attestation, receipts,
/// commitment refs and hosts. Borsh files; nothing here is readable
/// without the secret except the public genesis and roster.
public struct ClientStore: Sendable {
    public let directory: String
    public init(directory: String) {
        self.directory = directory
        try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    }

    // MARK: identity

    public func loadIdentity() -> ConvoIdentity? {
        guard let data = FileManager.default.contents(atPath: directory + "/identity.key"), data.count == 32 else { return nil }
        return try? ConvoIdentity(seed: Array(data))
    }

    public func saveIdentity(_ identity: ConvoIdentity) {
        let path = directory + "/identity.key"
        try? Data(identity.key.seed).write(to: URL(fileURLWithPath: path), options: .atomic)
        chmod(path, 0o600)
    }

    public var name: String? {
        get { try? String(contentsOfFile: directory + "/name", encoding: .utf8) }
        nonmutating set { try? newValue?.write(toFile: directory + "/name", atomically: true, encoding: .utf8) }
    }

    public var nodeURLs: [String] {
        get { (try? String(contentsOfFile: directory + "/nodes", encoding: .utf8))?.split(separator: "\n").map(String.init) ?? [] }
        nonmutating set { try? newValue.joined(separator: "\n").write(toFile: directory + "/nodes", atomically: true, encoding: .utf8) }
    }

    // MARK: groups

    private func groupDir(_ id: Hash32) -> String { directory + "/groups/" + id.hex }

    public var groupIDs: [Hash32] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory + "/groups")) ?? []).compactMap { Hash32(hex: $0) }.sorted()
    }

    public func saveGroup(_ session: GroupSession) async {
        let dir = groupDir(session.groupID)
        for sub in ["messages", "attestations", "receipts", "commitments"] {
            try? FileManager.default.createDirectory(atPath: dir + "/" + sub, withIntermediateDirectories: true)
        }
        write(dir + "/genesis.bin", session.genesis.borsh)
        var w = BorshWriter()
        w.vec(session.roster) { w, k in w.vec(k.wire) }
        write(dir + "/roster.bin", w.bytes)
        if let mls = await session.mlsState {
            var m = BorshWriter(); m.vec(mls.commitSecret); m.u32(mls.ownGeneration); m.u64(mls.epoch); m.u64(mls.updatedAt)
            write(dir + "/mls.bin", m.bytes)
            chmod(dir + "/mls.bin", 0o600)
        }
        let dag = await session.dag
        for (hash, signed) in dag.messages {
            let path = dir + "/messages/" + hash.hex + ".bin"
            if !FileManager.default.fileExists(atPath: path) { write(path, signed.wire) }
        }
        for att in dag.allAttestations {
            let path = dir + "/attestations/" + att.itemHash.hex + ".bin"
            if !FileManager.default.fileExists(atPath: path) { write(path, att.wire) }
        }
        for (_, byItem) in await session.receipts {
            for (_, receipt) in byItem {
                let path = dir + "/receipts/" + receipt.body.preimage.hex + ".bin"
                if !FileManager.default.fileExists(atPath: path) { write(path, receipt.wire) }
            }
        }
        for (item, ref) in await session.commitments {
            let path = dir + "/commitments/" + item.hex + ".bin"
            if !FileManager.default.fileExists(atPath: path) { write(path, ref.borsh) }
        }
        var e = BorshWriter()
        e.vec(await session.extraHosts) { w, h in w.fixed(h) }
        write(dir + "/hosts.bin", e.bytes)
        var pm = BorshWriter()
        pm.vec(await session.parentMembers) { w, m in w.fixed(m) }
        write(dir + "/parent.bin", pm.bytes)
        var rs = BorshWriter()
        rs.vec(Array(await session.resolvedSources)) { w, r in w.vec(r.borsh) }
        write(dir + "/resolved.bin", rs.bytes)
    }

    public func loadGroup(_ id: Hash32, identity: ConvoIdentity) async -> GroupSession? {
        let dir = groupDir(id)
        guard let g = read(dir + "/genesis.bin").flatMap({ try? Genesis.decode($0) }),
              let rosterBytes = read(dir + "/roster.bin"), let mlsBytes = read(dir + "/mls.bin") else { return nil }
        var r = BorshReader(rosterBytes)
        guard let roster = try? r.vec({ try KeyPackage.fromWire(try $0.vec()) }) else { return nil }
        var m = BorshReader(mlsBytes)
        guard let secret = try? m.vec(), let generation = try? m.u32() else { return nil }
        let epoch = (try? m.u64()) ?? 1
        let updatedAt = (try? m.u64()) ?? 0
        guard let session = try? GroupSession(genesis: g, roster: roster, identity: identity, commitSecret: secret, ownGeneration: generation, epoch: epoch, updatedAt: updatedAt) else { return nil }
        if let pm = read(dir + "/parent.bin") {
            var pr = BorshReader(pm)
            if let members = try? pr.vec({ try $0.hash32() }), !members.isEmpty { await session.setParent(members: members) }
        }
        // Messages in an order that satisfies parents: retry the orphans.
        var pending = files(dir + "/messages").compactMap { try? SignedMessage.fromWire($0) }
        var progress = true
        while progress, !pending.isEmpty {
            progress = false
            var next: [SignedMessage] = []
            for signed in pending {
                if (try? await session.receive(signed)) != nil { progress = true } else { next.append(signed) }
            }
            pending = next
        }
        for att in files(dir + "/attestations").compactMap({ try? SignedAttestation.fromWire($0) }) { await session.receive(att) }
        for receipt in files(dir + "/receipts").compactMap({ try? Receipt.fromWire($0) }) { await session.recordReceipt(receipt) }
        for ref in files(dir + "/commitments").compactMap({ try? CommitmentRef.decode($0) }) { await session.markCommitted(ref) }
        if let hosts = read(dir + "/hosts.bin") {
            var hr = BorshReader(hosts)
            for h in (try? hr.vec { try $0.hash32() }) ?? [] { await session.adoptHost(h) }
        }
        if let resolved = read(dir + "/resolved.bin") {
            var rr = BorshReader(resolved)
            for ref in (try? rr.vec { try CommitmentRef.decode(try $0.vec()) }) ?? [] { await session.markResolved(ref) }
        }
        return session
    }

    // MARK: fraud proofs (§17), kept and gossiped

    public func saveFraud(_ proof: FraudProof) {
        let dir = directory + "/fraud"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        write(dir + "/" + Hashing.sha256(proof.wire).hex + ".bin", proof.wire)
    }

    public var fraudProofs: [FraudProof] { files(directory + "/fraud").compactMap { try? FraudProof.fromWire($0) } }

    // MARK: handshakes in flight

    private var handshakeDir: String { directory + "/handshakes" }

    public func saveHandshake(salt: Hash32, role: String, bytes: [UInt8]) {
        try? FileManager.default.createDirectory(atPath: handshakeDir, withIntermediateDirectories: true)
        let path = "\(handshakeDir)/\(salt.hex).\(role)"
        write(path, bytes)
        chmod(path, 0o600)
    }

    public func loadHandshake(salt: Hash32, role: String) -> [UInt8]? { read("\(handshakeDir)/\(salt.hex).\(role)") }
    public func forgetHandshake(salt: Hash32) {
        for role in ["creator", "joiner"] { try? FileManager.default.removeItem(atPath: "\(handshakeDir)/\(salt.hex).\(role)") }
    }

    public func forgetGroup(_ id: Hash32) { try? FileManager.default.removeItem(atPath: groupDir(id)) }

    private func write(_ path: String, _ bytes: [UInt8]) { try? Data(bytes).write(to: URL(fileURLWithPath: path), options: .atomic) }
    private func read(_ path: String) -> [UInt8]? { FileManager.default.contents(atPath: path).map(Array.init) }
    private func files(_ dir: String) -> [[UInt8]] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).sorted().compactMap { read(dir + "/" + $0) }
    }
}
