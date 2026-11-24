import ConvoFoundation

/// A member's standing request to a host: when an item lands in this
/// group, call `url` with `handle` (Docs/deviations.md, "wakes"). The node
/// learns a relay's address and an opaque handle, nothing about what the
/// relay does with it; the relay learns that some device is to be woken
/// and which item, never the group. Signed by the member's group key; the
/// host keeps one per member per group until `expires` (unix ms), and a
/// registration with an empty handle takes the member's back.
public struct WakeRegistration: Hashable, Sendable {
    public struct Body: Hashable, Sendable, BorshCodable {
        public var memberPk: Hash32
        public var nodePk: Hash32
        public var groupID: Hash32
        public var url: String
        public var handle: [UInt8]
        public var expires: UInt64

        public init(memberPk: Hash32, nodePk: Hash32, groupID: Hash32, url: String, handle: [UInt8], expires: UInt64) {
            self.memberPk = memberPk; self.nodePk = nodePk; self.groupID = groupID; self.url = url; self.handle = handle; self.expires = expires
        }

        public var preimage: Hash32 { Hashing.hash(Domain.wake, borsh) }
        public func borshEncode(into w: inout BorshWriter) {
            w.fixed(memberPk); w.fixed(nodePk); w.fixed(groupID); w.string(url); w.vec(handle); w.u64(expires)
        }
        public init(borshFrom r: inout BorshReader) throws {
            memberPk = try r.hash32(); nodePk = try r.hash32(); groupID = try r.hash32(); url = try r.string(); handle = try r.vec(); expires = try r.u64()
        }
    }

    /// The most a handle may carry; a relay needs no more than a key's
    /// worth to find its device.
    public static let maxHandleBytes = 256
    /// The furthest ahead a registration may run (ms).
    public static let maxLifetimeMs: UInt64 = Parameters.Node.wakeLifetimeMs

    public let body: Body
    public let signature: [UInt8]

    public init(body: Body, signature: [UInt8]) { self.body = body; self.signature = signature }
    public static func sign(_ body: Body, with groupKey: SigningKey) -> WakeRegistration { WakeRegistration(body: body, signature: groupKey.sign(body.preimage)) }
    public var isValid: Bool { Signature.verify(signature, hash: body.preimage, publicKey: body.memberPk) }
    /// An empty handle asks the host to forget the member's registration.
    public var isRemoval: Bool { body.handle.isEmpty }
    public var wire: [UInt8] { body.borsh + signature }
    public static func fromWire(_ bytes: [UInt8]) throws -> WakeRegistration {
        guard bytes.count > 64 else { throw BorshError("wake registration too short") }
        return WakeRegistration(body: try Body.decode(Array(bytes.dropLast(64))), signature: Array(bytes.suffix(64)))
    }
}

/// What a host sends a relay when an item lands: the handle back, the
/// item's hash, the item's bytes when they are small enough to ride along
/// (sealed, so the relay sees what the node sees), signed by the node key
/// so a relay can take calls from registered nodes only. Carried as JSON
/// (hex and base64 fields) since relays are ordinary web services.
public struct WakeCall: Codable, Hashable, Sendable {
    public var node: String
    /// Unix ms.
    public var time: UInt64
    public var handle: String
    public var item: String
    public var body: String?
    public var sig: String

    /// Items above this ride as a hash only; the device fetches the rest.
    public static let maxBodyBytes = 4096

    public static func preimage(node: Hash32, handle: [UInt8], item: Hash32, time: UInt64) -> Hash32 {
        Hashing.hash(Domain.wakeCall, node.bytes, handle, item.bytes, withUnsafeBytes(of: time.littleEndian, Array.init))
    }

    public static func sign(handle: [UInt8], item: Hash32, body: [UInt8]?, time: UInt64, with nodeKey: SigningKey) -> WakeCall {
        let pk = nodeKey.publicKey
        let sig = nodeKey.sign(preimage(node: pk, handle: handle, item: item, time: time))
        return WakeCall(node: pk.hex, time: time, handle: handle.hex, item: item.hex,
                        body: body.map { Data($0).base64EncodedString() }, sig: sig.hex)
    }

    /// The signer, when the call is well formed and signed by the node it names.
    public var signer: Hash32? {
        guard let pk = Hash32(hex: node), let handle = [UInt8](hex: handle), let item = Hash32(hex: item),
              let sig = [UInt8](hex: sig), sig.count == 64,
              Signature.verify(sig, hash: Self.preimage(node: pk, handle: handle, item: item, time: time), publicKey: pk) else { return nil }
        return pk
    }
}
