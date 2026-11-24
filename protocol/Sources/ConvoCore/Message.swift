import ConvoFoundation

/// §3: one message. Append-only; `parents` make the DAG; `payload` is MLS ciphertext.
public struct Message: Hashable, Sendable, BorshCodable {
    public static let currentVersion: UInt8 = 1

    /// 3 and 4 are additions to revision 2 (Docs/deviations.md): a reaction
    /// to another message, and an attachment kept as a blob at the hosts.
    public enum Kind: UInt8, Sendable { case chat = 0, control = 1, republish = 2, reaction = 3, attachment = 4 }

    public var version: UInt8
    public var groupID: Hash32
    public var authorIdx: UInt8
    /// Per author, strictly increasing within the group.
    public var seq: UInt64
    /// 1...max_parents; an author's first message: [group_id].
    public var parents: [Hash32]
    /// Unix ms, advisory only.
    public var ts: UInt64
    public var kind: UInt8
    public var payload: [UInt8]

    public init(version: UInt8 = Message.currentVersion, groupID: Hash32, authorIdx: UInt8, seq: UInt64,
                parents: [Hash32], ts: UInt64, kind: Kind, payload: [UInt8]) {
        self.version = version
        self.groupID = groupID
        self.authorIdx = authorIdx
        self.seq = seq
        self.parents = parents
        self.ts = ts
        self.kind = kind.rawValue
        self.payload = payload
    }

    public var hash: Hash32 { Hashing.hash(Domain.message, borsh) }

    public func borshEncode(into w: inout BorshWriter) {
        w.u8(version); w.fixed(groupID); w.u8(authorIdx); w.u64(seq)
        w.vec(parents) { w, p in w.fixed(p) }
        w.u64(ts); w.u8(kind); w.vec(payload)
    }

    public init(borshFrom r: inout BorshReader) throws {
        version = try r.u8(); groupID = try r.hash32(); authorIdx = try r.u8(); seq = try r.u64()
        parents = try r.vec { try $0.hash32() }
        ts = try r.u64(); kind = try r.u8(); payload = try r.vec()
    }
}

/// A message with its author's signature: what mailboxes store and peers exchange.
public struct SignedMessage: Hashable, Sendable {
    public let message: Message
    public let signature: [UInt8]
    public let hash: Hash32

    public init(message: Message, signature: [UInt8]) {
        self.message = message
        self.signature = signature
        self.hash = message.hash
    }

    public static func sign(_ message: Message, with groupKey: SigningKey) -> SignedMessage {
        SignedMessage(message: message, signature: groupKey.sign(message.hash))
    }

    public func verify(author: Hash32) -> Bool {
        Signature.verify(signature, hash: hash, publicKey: author)
    }

    /// The content leaf (§4): `H("convo/leaf" ‖ borsh(Message) ‖ msg_sig)`.
    /// Also a receipt's `content_digest` for a message (§14).
    public var leaf: Hash32 { Hashing.hash(Domain.leaf, message.borsh, signature) }

    /// Wire form: borsh(Message) ‖ sig, as mailboxes store and serve it.
    public var wire: [UInt8] { message.borsh + signature }

    public static func fromWire(_ bytes: [UInt8]) throws -> SignedMessage {
        guard bytes.count > 64 else { throw BorshError("message wire too short") }
        let message = try Message.decode(Array(bytes.dropLast(64)))
        return SignedMessage(message: message, signature: Array(bytes.suffix(64)))
    }
}
