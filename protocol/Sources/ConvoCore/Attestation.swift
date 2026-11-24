import ConvoFoundation

/// §5: a member's signature over a head and its content root. An item
/// like a message: receipted and committed by home nodes.
public struct Attestation: Hashable, Sendable, BorshCodable {
    public var groupID: Hash32
    public var head: Hash32
    public var contentRoot: Hash32
    public var msgCount: UInt64
    public var signerIdx: UInt8

    public init(groupID: Hash32, head: Hash32, contentRoot: Hash32, msgCount: UInt64, signerIdx: UInt8) {
        self.groupID = groupID; self.head = head; self.contentRoot = contentRoot; self.msgCount = msgCount; self.signerIdx = signerIdx
    }

    /// `H("convo/att" ‖ borsh)`: what the signer signs, and the item hash.
    public var preimage: Hash32 { Hashing.hash(Domain.attestation, borsh) }
    public var itemHash: Hash32 { preimage }

    public func borshEncode(into w: inout BorshWriter) {
        w.fixed(groupID); w.fixed(head); w.fixed(contentRoot); w.u64(msgCount); w.u8(signerIdx)
    }

    public init(borshFrom r: inout BorshReader) throws {
        groupID = try r.hash32(); head = try r.hash32(); contentRoot = try r.hash32(); msgCount = try r.u64(); signerIdx = try r.u8()
    }
}

public struct SignedAttestation: Hashable, Sendable {
    public let attestation: Attestation
    public let signature: [UInt8]

    public init(attestation: Attestation, signature: [UInt8]) {
        self.attestation = attestation; self.signature = signature
    }

    public static func sign(_ attestation: Attestation, with groupKey: SigningKey) -> SignedAttestation {
        SignedAttestation(attestation: attestation, signature: groupKey.sign(attestation.preimage))
    }

    public func verify(signer: Hash32) -> Bool { Signature.verify(signature, hash: attestation.preimage, publicKey: signer) }

    public var itemHash: Hash32 { attestation.itemHash }

    /// Wire form: the attestation's borsh followed by the 64-byte signature.
    public var wire: [UInt8] { attestation.borsh + signature }
    public static func fromWire(_ bytes: [UInt8]) throws -> SignedAttestation {
        guard bytes.count > 64 else { throw BorshError("attestation wire too short") }
        var r = BorshReader(Array(bytes.dropLast(64)))
        let attestation = try Attestation(borshFrom: &r)
        try r.finish()
        return SignedAttestation(attestation: attestation, signature: Array(bytes.suffix(64)))
    }
}
