import ConvoCore
import ConvoMLS
import Crypto
import Foundation

/// A member: one Ed25519 identity (§1), from which the per-group signing
/// keys and the MLS leaf keys derive, so one 32-byte secret (or its
/// recovery phrase) backs everything.
public struct ConvoIdentity: Sendable {
    public let key: SigningKey
    public var publicKey: PublicKey { key.publicKey }

    public init(key: SigningKey) { self.key = key }
    public init(seed: [UInt8]) throws { key = try SigningKey(seed: seed) }
    public static func random() -> ConvoIdentity { ConvoIdentity(key: SigningKey.random()) }
    /// From a recovery phrase (§1).
    public init(words: [String], passphrase: String = "") throws { key = try IdentityKey.key(words: words, passphrase: passphrase) }
    /// From an exported secret key (64 or 32 bytes).
    public init(secretKey: [UInt8]) throws { key = try IdentityKey.key(secretKey: secretKey) }

    public func groupKey(salt: Hash32) -> SigningKey { key.groupKey(salt: salt) }

    /// The X25519 key MLS uses for this identity at `index` (§1): stable
    /// per index, so a KeyPackage is reproducible and a peer can address
    /// any device holding the secret; rotated on `HPKE_ROTATION`.
    public func hpkeKey(index: UInt32 = 0) -> Curve25519.KeyAgreement.PrivateKey {
        try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(key.hpkeSeed(index: index)))
    }

    /// The key package peers fetch from a node (`/v1/keypackages/<identity>`)
    /// to include this identity in a group.
    public func keyPackage(name: String, hpkeIndex: UInt32 = 0, notAfter: UInt64? = nil) -> KeyPackage {
        let expiry = notAfter ?? UInt64(Date().timeIntervalSince1970 + Parameters.Client.keyPackageLifetimeSeconds)
        let body = KeyPackage.Body(identityPk: publicKey, hpkeIndex: hpkeIndex, hpkePk: Array(hpkeKey(index: hpkeIndex).publicKey.rawRepresentation),
                                   notAfter: expiry, name: name)
        return KeyPackage(body: body, signature: key.sign(body.preimage))
    }
}

/// §2 KeyPackage: what an identity publishes so others can add it to a
/// group, signed by the identity so nobody can substitute a key.
public struct KeyPackage: Hashable, Sendable {
    public struct Body: Hashable, Sendable, BorshCodable {
        public static let currentVersion: UInt8 = 2
        public var version: UInt8
        public var identityPk: PublicKey
        public var hpkeIndex: UInt32
        public var hpkePk: [UInt8]
        /// Unix seconds; a creator must not use an expired KeyPackage.
        public var notAfter: UInt64
        public var name: String

        public init(version: UInt8 = Body.currentVersion, identityPk: PublicKey, hpkeIndex: UInt32, hpkePk: [UInt8], notAfter: UInt64, name: String) {
            precondition(hpkePk.count == 32)
            self.version = version; self.identityPk = identityPk; self.hpkeIndex = hpkeIndex; self.hpkePk = hpkePk; self.notAfter = notAfter; self.name = name
        }
        public var preimage: Hash32 { Hashing.hash(Domain.keyPackage, borsh) }
        public func borshEncode(into w: inout BorshWriter) {
            w.u8(version); w.fixed(identityPk); w.u32(hpkeIndex); w.fixed(hpkePk); w.u64(notAfter); w.string(name)
        }
        public init(borshFrom r: inout BorshReader) throws {
            version = try r.u8(); identityPk = try r.hash32(); hpkeIndex = try r.u32(); hpkePk = try r.fixed(32); notAfter = try r.u64(); name = try r.string()
        }
    }

    public let body: Body
    public let signature: [UInt8]
    public init(body: Body, signature: [UInt8]) { self.body = body; self.signature = signature }
    public var isValid: Bool { Signature.verify(signature, hash: body.preimage, publicKey: body.identityPk) }
    public func isExpired(at now: Date = Date()) -> Bool { Double(body.notAfter) < now.timeIntervalSince1970 }
    public var wire: [UInt8] { body.borsh + signature }
    public static func fromWire(_ bytes: [UInt8]) throws -> KeyPackage {
        guard bytes.count > 64 else { throw BorshError("key package too short") }
        let package = KeyPackage(body: try Body.decode(Array(bytes.dropLast(64))), signature: Array(bytes.suffix(64)))
        guard package.isValid else { throw BorshError("key package signature") }
        return package
    }
    /// Which of two packages for one identity a node keeps: the higher
    /// index, then the later expiry.
    public func supersedes(_ other: KeyPackage) -> Bool {
        body.hpkeIndex > other.body.hpkeIndex || (body.hpkeIndex == other.body.hpkeIndex && body.notAfter > other.body.notAfter)
    }
}
