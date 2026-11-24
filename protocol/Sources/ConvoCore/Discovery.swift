import ConvoFoundation

/// §13.2: a node an identity names, by key and where to reach it.
public struct NodeRef: Hashable, Sendable, BorshCodable {
    public var nodePk: PublicKey
    public var url: String

    public init(nodePk: PublicKey, url: String) { self.nodePk = nodePk; self.url = url }

    public func borshEncode(into w: inout BorshWriter) { w.fixed(nodePk); w.string(url) }
    public init(borshFrom r: inout BorshReader) throws { nodePk = try r.hash32(); url = try r.string() }
}

/// §13.2: the nodes that hold an identity's KeyPackages and receive its
/// invitations, signed by the identity. The newest valid record wins.
public struct IdentityRecord: Hashable, Sendable, BorshCodable {
    public static let currentVersion: UInt8 = 1
    public static let maxNodes = 8

    public var version: UInt8
    public var idPk: PublicKey
    public var nodes: [NodeRef]
    /// Unix ms.
    public var updated: UInt64
    public var signature: [UInt8]

    public init(version: UInt8 = IdentityRecord.currentVersion, idPk: PublicKey, nodes: [NodeRef], updated: UInt64, signature: [UInt8]) {
        self.version = version; self.idPk = idPk; self.nodes = nodes; self.updated = updated; self.signature = signature
    }

    public static func sign(nodes: [NodeRef], updated: UInt64, with identityKey: SigningKey) -> IdentityRecord {
        var record = IdentityRecord(idPk: identityKey.publicKey, nodes: nodes, updated: updated, signature: [])
        record.signature = identityKey.sign(record.preimage)
        return record
    }

    private func encodeFields(into w: inout BorshWriter) {
        w.u8(version); w.fixed(idPk); w.vec(nodes) { w, n in n.borshEncode(into: &w) }; w.u64(updated)
    }

    /// `H("convo/idrec" ‖ borsh(fields))`.
    public var preimage: Hash32 {
        var w = BorshWriter(); encodeFields(into: &w)
        return Hashing.hash(Domain.identityRecord, w.bytes)
    }

    public var isValid: Bool {
        version == Self.currentVersion && (1...Self.maxNodes).contains(nodes.count)
            && Signature.verify(signature, hash: preimage, publicKey: idPk)
    }

    public func borshEncode(into w: inout BorshWriter) { encodeFields(into: &w); w.fixed(signature) }
    public init(borshFrom r: inout BorshReader) throws {
        version = try r.u8(); idPk = try r.hash32(); nodes = try r.vec { try NodeRef(borshFrom: &$0) }
        updated = try r.u64(); signature = try r.fixed(64)
    }

    public var wire: [UInt8] { borsh }
    public static func fromWire(_ bytes: [UInt8]) throws -> IdentityRecord { try decode(bytes) }
}

/// §24: a node's description of itself, signed by its key. A node exists
/// when it serves a valid descriptor.
public struct NodeDescriptor: Hashable, Sendable, BorshCodable {
    public var nodePk: PublicKey
    /// Who runs it; one operator may run several nodes.
    public var operatorPk: PublicKey
    public var url: String
    /// Where it runs (a region or a name), advisory.
    public var site: String
    public var turn: Bool
    public var version: String
    /// Unix ms.
    public var time: UInt64
    public var signature: [UInt8]

    public init(nodePk: PublicKey, operatorPk: PublicKey, url: String, site: String, turn: Bool, version: String, time: UInt64, signature: [UInt8]) {
        self.nodePk = nodePk; self.operatorPk = operatorPk; self.url = url; self.site = site; self.turn = turn
        self.version = version; self.time = time; self.signature = signature
    }

    public static func sign(operatorPk: PublicKey, url: String, site: String, turn: Bool, version: String, time: UInt64,
                            with nodeKey: SigningKey) -> NodeDescriptor {
        var descriptor = NodeDescriptor(nodePk: nodeKey.publicKey, operatorPk: operatorPk, url: url, site: site, turn: turn,
                                        version: version, time: time, signature: [])
        descriptor.signature = nodeKey.sign(descriptor.preimage)
        return descriptor
    }

    private func encodeFields(into w: inout BorshWriter) {
        w.fixed(nodePk); w.fixed(operatorPk); w.string(url); w.string(site); w.bool(turn); w.string(version); w.u64(time)
    }

    /// `H("convo/nodedesc" ‖ borsh(fields))`.
    public var preimage: Hash32 {
        var w = BorshWriter(); encodeFields(into: &w)
        return Hashing.hash(Domain.nodeDescriptor, w.bytes)
    }

    public var isValid: Bool { Signature.verify(signature, hash: preimage, publicKey: nodePk) }

    public func borshEncode(into w: inout BorshWriter) { encodeFields(into: &w); w.fixed(signature) }
    public init(borshFrom r: inout BorshReader) throws {
        nodePk = try r.hash32(); operatorPk = try r.hash32(); url = try r.string(); site = try r.string()
        turn = try r.bool(); version = try r.string(); time = try r.u64(); signature = try r.fixed(64)
    }
}
