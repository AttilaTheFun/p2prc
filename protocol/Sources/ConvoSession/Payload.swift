import ConvoCore
import ConvoMLS
import Crypto
import Foundation

/// What goes in a `Message.payload` (§3): a sealed MLS application message
/// for `kind = chat`, an MLS commit for `kind = control`, a `Republish`
/// for `kind = republish`. Borsh, one tag byte first.
public enum GroupPayload {
    public static let sealedTag: UInt8 = 0, commitTag: UInt8 = 1

    public static func encode(_ sealed: MLSGroup.Sealed) -> [UInt8] {
        var w = BorshWriter()
        w.u8(sealedTag); w.u64(sealed.epoch); w.string(sealed.sender); w.u32(sealed.generation); w.vec(Array(sealed.ciphertext))
        return w.bytes
    }

    public static func decodeSealed(_ bytes: [UInt8]) throws -> MLSGroup.Sealed {
        var r = BorshReader(bytes)
        guard try r.u8() == sealedTag else { throw BorshError("not a sealed payload") }
        let sealed = MLSGroup.Sealed(epoch: try r.u64(), sender: try r.string(), generation: try r.u32(), ciphertext: Data(try r.vec()))
        try r.finish()
        return sealed
    }

    public static func encode(_ commit: MLSGroup.Commit) -> [UInt8] {
        var w = BorshWriter()
        w.u8(commitTag)
        w.string(commit.id); w.u64(commit.epoch); w.string(commit.committer)
        w.vec(commit.members) { w, m in w.string(m.id); w.string(m.name); w.vec(Array(m.publicKey)) }
        w.u32(UInt32(commit.path.leaf)); w.vec(Array(commit.path.leafPublicKey))
        w.vec(commit.path.steps) { w, s in
            w.u32(UInt32(s.node)); w.vec(Array(s.publicKey))
            w.vec(s.encrypted) { w, e in w.u32(UInt32(e.to)); w.vec(Array(e.kem)); w.vec(Array(e.ciphertext)) }
        }
        // The leaf secret sealed to the committer's own key (empty when none).
        w.vec(Array(commit.ownSealed?.kem ?? Data())); w.vec(Array(commit.ownSealed?.ciphertext ?? Data()))
        return w.bytes
    }

    public static func decodeCommit(_ bytes: [UInt8]) throws -> MLSGroup.Commit {
        var r = BorshReader(bytes)
        guard try r.u8() == commitTag else { throw BorshError("not a commit payload") }
        let id = try r.string(), epoch = try r.u64(), committer = try r.string()
        let members = try r.vec { r in MLSGroup.Member(id: try r.string(), name: try r.string(), publicKey: Data(try r.vec())) }
        let leaf = Int(try r.u32()), leafPk = Data(try r.vec())
        let steps = try r.vec { r -> RatchetTree.UpdatePath.Step in
            let node = Int(try r.u32()), pk = Data(try r.vec())
            let encrypted = try r.vec { r -> (to: Int, kem: Data, ciphertext: Data) in (Int(try r.u32()), Data(try r.vec()), Data(try r.vec())) }
            return .init(node: node, publicKey: pk, encrypted: encrypted)
        }
        var ownSealed: (kem: Data, ciphertext: Data)?
        if !r.isAtEnd {
            let kem = try r.vec(), ciphertext = try r.vec()
            if !kem.isEmpty { ownSealed = (Data(kem), Data(ciphertext)) }
        }
        try r.finish()
        return MLSGroup.Commit(id: id, epoch: epoch, committer: committer, path: .init(leaf: leaf, leafPublicKey: leafPk, steps: steps), members: members, ownSealed: ownSealed)
    }
}
