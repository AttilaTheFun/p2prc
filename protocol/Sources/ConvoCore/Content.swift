import ConvoFoundation

/// Message kinds 3 and 4 (an addition to revision 2). Both travel sealed
/// like chat: the payload is MLS ciphertext of `"react:" ‖ hex(borsh)` or
/// `"attach:" ‖ hex(borsh)`, so a node sees only the kind byte.

/// Kind 3: an emoji on another message of the group. A second reaction
/// by the same author with the same emoji and `remove` set takes the
/// first back; readers fold them in canonical order (§4).
public struct Reaction: Hashable, Sendable, BorshCodable {
    public var target: Hash32
    public var emoji: String
    public var remove: Bool

    public init(target: Hash32, emoji: String, remove: Bool = false) {
        self.target = target; self.emoji = emoji; self.remove = remove
    }
    public func borshEncode(into w: inout BorshWriter) { w.fixed(target); w.string(emoji); w.bool(remove) }
    public init(borshFrom r: inout BorshReader) throws { target = try r.hash32(); emoji = try r.string(); remove = try r.bool() }
}

/// Kind 4: a picture (or any file) whose sealed bytes live in the group's
/// blob store at its home nodes (§13, `POST /v1/groups/<g>/blobs/<sha256>`).
/// `blob` names the sealed bytes; `key` opens them (ChaCha20-Poly1305,
/// nonce ‖ ciphertext ‖ tag); the rest lets a thread lay the tile out
/// before the bytes arrive.
public struct Attachment: Hashable, Sendable, BorshCodable {
    public var blob: Hash32
    public var key: [UInt8]
    public var mime: String
    public var width: UInt32
    public var height: UInt32
    /// The sealed byte count.
    public var size: UInt64
    public var caption: String

    public init(blob: Hash32, key: [UInt8], mime: String, width: UInt32, height: UInt32, size: UInt64, caption: String = "") {
        self.blob = blob; self.key = key; self.mime = mime; self.width = width; self.height = height; self.size = size; self.caption = caption
    }
    public func borshEncode(into w: inout BorshWriter) {
        w.fixed(blob); w.vec(key); w.string(mime); w.u32(width); w.u32(height); w.u64(size); w.string(caption)
    }
    public init(borshFrom r: inout BorshReader) throws {
        blob = try r.hash32(); key = try r.vec(); mime = try r.string(); width = try r.u32(); height = try r.u32(); size = try r.u64(); caption = try r.string()
    }
}
