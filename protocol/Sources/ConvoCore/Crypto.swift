import Crypto
import ConvoFoundation

// §1 and Appendix A.2: SHA-256 with an ASCII domain tag prepended to the
// borsh bytes; Ed25519 signatures over the tagged hash; per-group signing
// keys and MLS leaf keys derived from the identity key with HKDF.

/// A 32-byte Ed25519 public key (a member's gk, a node's key, an identity).
public typealias PublicKey = Hash32

public enum Domain {
    public static let genesis = "convo/genesis"
    public static let message = "convo/msg"
    public static let leaf = "convo/leaf"
    public static let node = "convo/node"
    public static let attestation = "convo/att"
    public static let fork = "convo/fork"
    public static let sync = "convo/sync"
    public static let receipt = "convo/rcpt"
    public static let fetch = "convo/fetch"
    /// §19: a signed `GET` (member-only routes).
    public static let get = "convo/get"
    public static let response = "convo/resp"
    public static let ack = "convo/ack"
    /// Wakes (Docs/deviations.md): a member's registration with a host, and
    /// a host's call to the relay.
    public static let wake = "convo/wake"
    public static let wakeCall = "convo/wakecall"
    public static let commitmentBatch = "convo/cbatch"
    public static let gap = "convo/gap"
    public static let gapNode = "convo/gnode"
    public static let commitmentLeaf = "convo/cbatch-leaf"
    public static let mmrNode = "convo/mmr-node"
    /// §6, §11: a node's checkpoint of its log, and a witness's cosignature.
    public static let checkpoint = "convo/ckpt"
    public static let cosignature = "convo/cosign"
    public static let keyPackage = "convo/kp"
    /// §13.2 and §24: an identity's record of its nodes; a node's descriptor.
    public static let identityRecord = "convo/idrec"
    public static let nodeDescriptor = "convo/nodedesc"
    /// §1: the identity key from a recovery phrase's seed (HKDF info).
    public static let identityInfo = "convo/identity/v1"
    public static let rendezvous = "convo/rv"
    public static let groupKeyInfo = "convo/gk/v1"
    public static let hpkeInfo = "convo/hpke/v1"
}

public enum Hashing {
    /// `H(tag ‖ bytes)`.
    public static func hash(_ tag: String, _ parts: [UInt8]...) -> Hash32 {
        var h = SHA256()
        h.update(data: Array(tag.utf8))
        for part in parts { h.update(data: part) }
        return Hash32(Array(h.finalize()))
    }

    public static func sha256(_ bytes: [UInt8]) -> Hash32 {
        Hash32(Array(SHA256.hash(data: bytes)))
    }
}

/// An Ed25519 signing key: an identity (`id_sk`, its
/// 32-byte secret) or a per-group key (`gk`).
public struct SigningKey: @unchecked Sendable {   // immutable; swift-crypto's PrivateKey is not Sendable on Linux
    public let seed: [UInt8]
    private let key: Curve25519.Signing.PrivateKey

    public init(seed: [UInt8]) throws {
        self.seed = seed
        self.key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    public static func random() -> SigningKey {
        let key = Curve25519.Signing.PrivateKey()
        return try! SigningKey(seed: Array(key.rawRepresentation))
    }

    public var publicKey: Hash32 { Hash32(Array(key.publicKey.rawRepresentation)) }

    /// A 64-byte Ed25519 signature over `hash` (the tagged preimage hash).
    public func sign(_ hash: Hash32) -> [UInt8] {
        Array(try! key.signature(for: hash.bytes))
    }

    /// The per-group signing key (§1): HKDF-SHA256 over the identity seed
    /// with the genesis salt and the fixed info.
    public func groupKey(salt: Hash32) -> SigningKey {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed), salt: salt.bytes,
            info: Array(Domain.groupKeyInfo.utf8), outputByteCount: 32
        )
        return try! SigningKey(seed: derived.withUnsafeBytes { Array($0) })
    }

    /// The MLS leaf key at index `n` (§1): `HKDF(ikm = id_sk, salt = n as
    /// u32 LE, info = "convo/hpke/v1")` as an X25519 private key's raw bytes.
    public func hpkeSeed(index: UInt32) -> [UInt8] {
        var salt = BorshWriter(); salt.u32(index)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed), salt: salt.bytes,
            info: Array(Domain.hpkeInfo.utf8), outputByteCount: 32
        )
        return derived.withUnsafeBytes { Array($0) }
    }
}

public enum Signature {
    public static func verify(_ signature: [UInt8], hash: Hash32, publicKey: Hash32) -> Bool {
        guard signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey.bytes) else { return false }
        return key.isValidSignature(signature, for: hash.bytes)
    }

    public static func verifyRaw(_ signature: [UInt8], message: [UInt8], publicKey: Hash32) -> Bool {
        guard signature.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey.bytes) else { return false }
        return key.isValidSignature(signature, for: message)
    }
}
