import ConvoCore
import ConvoFoundation

/// The node's HTTP surface (Part III §19). Bodies are the Part I/II wire
/// objects; JSON only where a list or a record is returned. See
/// Docs/node-api.md.
public enum NodeAPI {
    /// POST binary item → Receipt wire. Item kinds by path.
    public static func item(_ groupID: Hash32, kind: ItemKind) -> String { "/v1/groups/\(groupID.hex)/\(kind.path)" }
    /// POST FetchRequest wire → FetchResponse wire ‖ items (see `FetchReply`).
    public static func fetch(_ groupID: Hash32) -> String { "/v1/groups/\(groupID.hex)/fetch" }
    /// GET → JSON list of the attestations the node holds for the group (members only).
    public static func attestations(_ groupID: Hash32) -> String { "/v1/groups/\(groupID.hex)/attestations" }
    /// POST Genesis wire ‖ carries (see `GenesisRecord`) → 204; GET → the same (members only).
    public static func genesis(_ groupID: Hash32) -> String { "/v1/groups/\(groupID.hex)/genesis" }
    /// POST Ack wire → 204.
    public static func ack(_ groupID: Hash32) -> String { "/v1/groups/\(groupID.hex)/acks" }
    /// POST blob bytes → Receipt; GET by content hash.
    public static func blob(_ groupID: Hash32, _ hash: Hash32) -> String { "/v1/groups/\(groupID.hex)/blobs/\(hash.hex)" }
    /// POST WakeRegistration wire → 204: call the member's relay when an item lands (deviations: wakes).
    public static func wake(_ groupID: Hash32) -> String { "/v1/groups/\(groupID.hex)/wake" }
    /// POST/GET KeyPackage bytes by identity (POST → Receipt wire).
    public static func keyPackage(_ identity: Hash32) -> String { "/v1/keypackages/\(identity.hex)" }
    /// GET → CommitmentRef wire for an item this node committed (members only).
    public static func commitment(_ itemHash: Hash32) -> String { "/v1/items/\(itemHash.hex)/commitment" }
    /// GET → CommitmentBatch wire; POST (a committing node pushing a body) → 204.
    public static func batches(_ nodePk: Hash32) -> String { "/v1/notary/\(nodePk.hex)/batches" }
    public static func batch(_ nodePk: Hash32, seq: UInt64) -> String { "/v1/notary/\(nodePk.hex)/batches/\(seq)" }
    /// GET → MmrProof wire of that batch's leaf against the node's current peaks.
    public static func batchProof(_ nodePk: Hash32, seq: UInt64) -> String { "/v1/notary/\(nodePk.hex)/batches/\(seq)/proof" }
    /// GET → the newest `WitnessedCheckpoint` this node holds for that log (§11).
    public static func checkpoint(_ nodePk: Hash32) -> String { "/v1/notary/\(nodePk.hex)/checkpoint" }
    /// POST `WitnessRequest` wire → `Cosignature` wire, or 409 with the witness's newest checkpoint for the log (§11).
    public static let witness = "/v1/witness"
    /// POST FraudProof wire → 202 when it verifies (§17); GET `?node=<pk>` → JSON hex list.
    public static let fraud = "/v1/fraud"
    public static func fraud(against nodePk: Hash32) -> String { "/v1/fraud?node=\(nodePk.hex)" }
    /// POST `IdentityRecord` wire → Receipt wire; GET → the newest record (§13.2).
    public static func identity(_ idPk: Hash32) -> String { "/v1/identities/\(idPk.hex)" }
    /// GET → JSON `NodeInfo`: the node's signed descriptor and its terms (§24).
    public static let info = "/v1/node"
    public static let health = "/health"
    /// GET → JSON `ICEAnswer`: STUN and TURN with short-lived credentials (§21).
    public static let ice = "/ice"
    /// POST text / GET text: a rendezvous box (§20).
    public static func rendezvous(_ box: String) -> String { "/rendezvous/\(box)" }
    /// The box for frames addressed to one identity about one salt.
    public static func handshakeBox(salt: Hash32, recipient: Hash32) -> String { String(Hashing.hash("convo/hs", salt.bytes, recipient.bytes).hex.prefix(64)) }
    /// §19: member-only `GET`s carry
    /// `X-Convo-Auth: <hex pubkey> <hex time> <hex sig>`, the signature over
    /// `H("convo/get" ‖ method ‖ path-and-query ‖ time)`, time in unix ms.
    public static let authHeader = "X-Convo-Auth"
    /// How far (ms) a signed GET's time may sit from the node's clock.
    public static let authWindowMs: UInt64 = Parameters.Node.requestMaxAheadMs

    public static func getAuthPreimage(method: String, pathAndQuery: String, time: UInt64) -> Hash32 {
        Hashing.hash(Domain.get, Array(method.utf8), Array(pathAndQuery.utf8), withUnsafeBytes(of: time.littleEndian, Array.init))
    }

    /// The header value a client sends.
    public static func getAuth(key: SigningKey, method: String = "GET", pathAndQuery: String, time: UInt64) -> String {
        let sig = key.sign(getAuthPreimage(method: method, pathAndQuery: pathAndQuery, time: time))
        return "\(key.publicKey.hex) \(String(time, radix: 16)) \(sig.hex)"
    }

    /// The header parsed: the signer, if the header is well formed and the
    /// signature verifies for this request; the caller checks the time and
    /// whether the signer is allowed.
    public static func verifyGetAuth(_ header: String, method: String, pathAndQuery: String) -> (signer: PublicKey, time: UInt64)? {
        let parts = header.split(separator: " ").map(String.init)
        guard parts.count == 3, let pk = Hash32(hex: parts[0]), let time = UInt64(parts[1], radix: 16),
              let sig = [UInt8](hex: parts[2]), sig.count == 64 else { return nil }
        guard Signature.verify(sig, hash: getAuthPreimage(method: method, pathAndQuery: pathAndQuery, time: time), publicKey: pk) else { return nil }
        return (pk, time)
    }

    public enum ItemKind: String, Sendable {
        case message = "messages", attestation = "attestations", republish = "republishes"
        var path: String { rawValue }
    }

    /// Identity-scoped items (KeyPackages, unattached blobs) are receipted under this group id.
    public static let identityGroup = Hash32.zero
}

/// A fetch's reply: the signed response followed by the served items,
/// each as u32-length-prefixed bytes (borsh vec) so one body carries all.
public struct FetchReply: Sendable {
    public let response: FetchResponse
    public let items: [[UInt8]]

    public init(response: FetchResponse, items: [[UInt8]]) { self.response = response; self.items = items }

    public var wire: [UInt8] {
        var w = BorshWriter()
        w.vec(response.wire)
        w.vec(items) { w, i in w.vec(i) }
        return w.bytes
    }

    public static func fromWire(_ bytes: [UInt8]) throws -> FetchReply {
        var r = BorshReader(bytes)
        let response = try FetchResponse.fromWire(try r.vec())
        let items = try r.vec { try $0.vec() }
        try r.finish()
        return FetchReply(response: response, items: items)
    }
}

/// What `/v1/node` returns (§24): the node's signed descriptor, byte
/// fields in hex, and its terms and state, which the signature does not cover.
public struct NodeInfo: Codable, Equatable, Sendable {
    public var nodePk: String
    public var operatorPk: String
    public var url: String
    public var site: String
    public var turn: Bool
    public var version: String
    public var time: UInt64
    public var sig: String
    public var id: String?
    public var stun: [String]?
    public var deliveryWindowMs: UInt64?
    public var retentionMs: UInt64?
    /// The node's clock (unix ms).
    public var now: UInt64?
    /// The batch the node is currently assembling (§7).
    public var batchSeq: UInt64?

    public init(descriptor d: NodeDescriptor, id: String? = nil, stun: [String]? = nil, deliveryWindowMs: UInt64? = nil,
                retentionMs: UInt64? = nil, now: UInt64? = nil, batchSeq: UInt64? = nil) {
        nodePk = d.nodePk.hex; operatorPk = d.operatorPk.hex; url = d.url; site = d.site; turn = d.turn
        version = d.version; time = d.time; sig = d.signature.hex
        self.id = id; self.stun = stun; self.deliveryWindowMs = deliveryWindowMs; self.retentionMs = retentionMs
        self.now = now; self.batchSeq = batchSeq
    }

    /// The descriptor, when its signature verifies.
    public var descriptor: NodeDescriptor? {
        guard let pk = Hash32(hex: nodePk), let op = Hash32(hex: operatorPk), let s = [UInt8](hex: sig), s.count == 64 else { return nil }
        let d = NodeDescriptor(nodePk: pk, operatorPk: op, url: url, site: site, turn: turn, version: version, time: time, signature: s)
        return d.isValid ? d : nil
    }
    public var publicKey: PublicKey? { descriptor?.nodePk }
    public var publicURL: String? { url.isEmpty ? nil : url }
}

/// `GET /v1/notary/<pk>/batches`: one batch's log entry.
public struct BatchLeaf: Codable, Equatable, Sendable {
    public var seq: UInt64
    public var root: String
    public var time: UInt64
    public var count: UInt64
    public init(seq: UInt64, root: String, time: UInt64, count: UInt64) { self.seq = seq; self.root = root; self.time = time; self.count = count }
    public var entry: LogEntry? { Hash32(hex: root).map { LogEntry(root: $0, time: time, count: count) } }
    public var leaf: Hash32? { entry?.leaf }
}

/// `GET /v1/groups/<id>/attestations`: one attestation the node holds.
public struct AttestationRecord: Codable, Equatable, Sendable {
    public var wire: String
    public var head: String
    public var contentRoot: String
    public var msgCount: UInt64
    public var signerIdx: UInt8
    /// The node's own `CommitmentRef` for it, hex borsh, once committed.
    public var committed: String?
    public init(_ signed: SignedAttestation, committed: CommitmentRef?) {
        wire = signed.wire.hex; head = signed.attestation.head.hex; contentRoot = signed.attestation.contentRoot.hex
        msgCount = signed.attestation.msgCount; signerIdx = signed.attestation.signerIdx; self.committed = committed?.borsh.hex
    }
    public var signed: SignedAttestation? { [UInt8](hex: wire).flatMap { try? SignedAttestation.fromWire($0) } }
    public var commitmentRef: CommitmentRef? { committed.flatMap { [UInt8](hex: $0) }.flatMap { try? CommitmentRef.decode($0) } }
}

/// `POST/GET /v1/groups/<id>/genesis`: the genesis bytes and the carry
/// signatures gossiped at the handshake (§2, §13).
public struct GenesisRecord: Hashable, Sendable {
    public var genesis: Genesis
    public var carrySigs: [(UInt8, [UInt8])]
    public init(genesis: Genesis, carrySigs: [(UInt8, [UInt8])]) { self.genesis = genesis; self.carrySigs = carrySigs }

    public var wire: [UInt8] {
        var w = BorshWriter()
        w.vec(genesis.borsh)
        w.vec(carrySigs) { w, s in w.u8(s.0); w.fixed(s.1) }
        return w.bytes
    }
    public static func fromWire(_ bytes: [UInt8]) throws -> GenesisRecord {
        var r = BorshReader(bytes)
        var g = BorshReader(try r.vec())
        let genesis = try Genesis(borshFrom: &g)
        try g.finish()
        let sigs = try r.vec { r -> (UInt8, [UInt8]) in (try r.u8(), try r.fixed(64)) }
        try r.finish()
        return GenesisRecord(genesis: genesis, carrySigs: sigs)
    }
    public static func == (a: GenesisRecord, b: GenesisRecord) -> Bool { a.wire == b.wire }
    public func hash(into hasher: inout Hasher) { hasher.combine(wire) }
}
