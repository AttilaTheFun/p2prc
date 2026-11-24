import ConvoFoundation

// Part II: the node accountability formats. Every object is signed over
// `H(tag ‖ borsh(fields))` with the sig field excluded from the fields.

/// §14: a node's promise to hold and deliver an item, and to put it in
/// the batch the receipt names.
public struct Receipt: Hashable, Sendable {
    public struct Body: Hashable, Sendable, BorshCodable {
        public var nodePk: Hash32
        public var groupID: Hash32
        public var itemHash: Hash32
        /// `SHA-256(bytes as received)`, untagged, for every item kind.
        public var contentDigest: Hash32
        /// The batch this item will be a leaf of (§6).
        public var batchSeq: UInt64
        /// The root of `batchSeq − 1` in the node's log (zeros for the first).
        public var batchPrev: Hash32
        /// Unix ms.
        public var received: UInt64
        public var deadline: UInt64
        public var retainUntil: UInt64

        public init(nodePk: Hash32, groupID: Hash32, itemHash: Hash32, contentDigest: Hash32, batchSeq: UInt64, batchPrev: Hash32,
                    received: UInt64, deadline: UInt64, retainUntil: UInt64) {
            self.nodePk = nodePk; self.groupID = groupID; self.itemHash = itemHash; self.contentDigest = contentDigest
            self.batchSeq = batchSeq; self.batchPrev = batchPrev
            self.received = received; self.deadline = deadline; self.retainUntil = retainUntil
        }

        public var preimage: Hash32 { Hashing.hash(Domain.receipt, borsh) }

        public func borshEncode(into w: inout BorshWriter) {
            w.fixed(nodePk); w.fixed(groupID); w.fixed(itemHash); w.fixed(contentDigest)
            w.u64(batchSeq); w.fixed(batchPrev)
            w.u64(received); w.u64(deadline); w.u64(retainUntil)
        }

        public init(borshFrom r: inout BorshReader) throws {
            nodePk = try r.hash32(); groupID = try r.hash32(); itemHash = try r.hash32(); contentDigest = try r.hash32()
            batchSeq = try r.u64(); batchPrev = try r.hash32()
            received = try r.u64(); deadline = try r.u64(); retainUntil = try r.u64()
        }
    }

    public let body: Body
    public let signature: [UInt8]

    public init(body: Body, signature: [UInt8]) { self.body = body; self.signature = signature }
    public static func sign(_ body: Body, with nodeKey: SigningKey) -> Receipt { Receipt(body: body, signature: nodeKey.sign(body.preimage)) }
    public var isValid: Bool { Signature.verify(signature, hash: body.preimage, publicKey: body.nodePk) }
    public var wire: [UInt8] { body.borsh + signature }
    /// Fixed size: five hashes, four u64, a 64-byte signature.
    public static let wireCount = 5 * 32 + 4 * 8 + 64
    public static func fromWire(_ bytes: [UInt8]) throws -> Receipt {
        guard bytes.count > 64 else { throw BorshError("receipt too short") }
        return Receipt(body: try Body.decode(Array(bytes.dropLast(64))), signature: Array(bytes.suffix(64)))
    }
}

/// §15: what a member wants from a node.
public enum FetchWant: Hashable, Sendable {
    case item(Hash32)
    /// Everything the node holds for the group not under `sinceHead`
    /// (all zeros: everything); `head` is what the requester wants held.
    case range(sinceHead: Hash32, head: Hash32)
    case blob(Hash32)
}

public struct FetchRequest: Hashable, Sendable {
    public struct Body: Hashable, Sendable, BorshCodable {
        public var requesterPk: Hash32
        public var groupID: Hash32
        public var want: FetchWant
        public var nonce: [UInt8]
        /// Unix ms.
        public var time: UInt64

        public init(requesterPk: Hash32, groupID: Hash32, want: FetchWant, nonce: [UInt8], time: UInt64) {
            precondition(nonce.count == 16)
            self.requesterPk = requesterPk; self.groupID = groupID; self.want = want; self.nonce = nonce; self.time = time
        }

        public var preimage: Hash32 { Hashing.hash(Domain.fetch, borsh) }

        public func borshEncode(into w: inout BorshWriter) {
            w.fixed(requesterPk); w.fixed(groupID)
            switch want {
            case .item(let h): w.u8(0); w.fixed(h)
            case .range(let since, let head): w.u8(1); w.fixed(since); w.fixed(head)
            case .blob(let h): w.u8(2); w.fixed(h)
            }
            w.fixed(nonce); w.u64(time)
        }

        public init(borshFrom r: inout BorshReader) throws {
            requesterPk = try r.hash32(); groupID = try r.hash32()
            switch try r.u8() {
            case 0: want = .item(try r.hash32())
            case 1: want = .range(sinceHead: try r.hash32(), head: try r.hash32())
            case 2: want = .blob(try r.hash32())
            default: throw BorshError("invalid fetch want tag")
            }
            nonce = try r.fixed(16); time = try r.u64()
        }
    }

    public let body: Body
    public let signature: [UInt8]

    public init(body: Body, signature: [UInt8]) { self.body = body; self.signature = signature }
    public static func sign(_ body: Body, with groupKey: SigningKey) -> FetchRequest { FetchRequest(body: body, signature: groupKey.sign(body.preimage)) }
    public var isValid: Bool { Signature.verify(signature, hash: body.preimage, publicKey: body.requesterPk) }
    /// `H("convo/fetch" ‖ borsh(FetchRequest))`: the request hash a response cites.
    public var requestHash: Hash32 { body.preimage }
    public var wire: [UInt8] { body.borsh + signature }
    public static func fromWire(_ bytes: [UInt8]) throws -> FetchRequest {
        guard bytes.count > 64 else { throw BorshError("fetch request too short") }
        return FetchRequest(body: try Body.decode(Array(bytes.dropLast(64))), signature: Array(bytes.suffix(64)))
    }
}

public enum FetchStatus: UInt8, Sendable { case found = 0, notFound = 1, partial = 2, unauthorized = 3, expired = 4 }

public struct FetchResponse: Hashable, Sendable {
    public struct Body: Hashable, Sendable, BorshCodable {
        public var nodePk: Hash32
        public var requestHash: Hash32
        public var status: UInt8
        /// (item_hash, content_digest = H(bytes as sent)).
        public var served: [(Hash32, Hash32)]
        /// Unix ms, never below the request's.
        public var time: UInt64

        public init(nodePk: Hash32, requestHash: Hash32, status: FetchStatus, served: [(Hash32, Hash32)], time: UInt64) {
            self.nodePk = nodePk; self.requestHash = requestHash; self.status = status.rawValue; self.served = served; self.time = time
        }

        public var preimage: Hash32 { Hashing.hash(Domain.response, borsh) }

        public func borshEncode(into w: inout BorshWriter) {
            w.fixed(nodePk); w.fixed(requestHash); w.u8(status)
            w.vec(served) { w, s in w.fixed(s.0); w.fixed(s.1) }
            w.u64(time)
        }

        public init(borshFrom r: inout BorshReader) throws {
            nodePk = try r.hash32(); requestHash = try r.hash32(); status = try r.u8()
            served = try r.vec { r in (try r.hash32(), try r.hash32()) }
            time = try r.u64()
        }

        public static func == (a: Body, b: Body) -> Bool { a.borsh == b.borsh }
        public func hash(into hasher: inout Hasher) { hasher.combine(borsh) }
    }

    public let body: Body
    public let signature: [UInt8]

    public init(body: Body, signature: [UInt8]) { self.body = body; self.signature = signature }
    public static func sign(_ body: Body, with nodeKey: SigningKey) -> FetchResponse { FetchResponse(body: body, signature: nodeKey.sign(body.preimage)) }
    public var isValid: Bool { Signature.verify(signature, hash: body.preimage, publicKey: body.nodePk) }
    public var wire: [UInt8] { body.borsh + signature }
    public static func fromWire(_ bytes: [UInt8]) throws -> FetchResponse {
        guard bytes.count > 64 else { throw BorshError("fetch response too short") }
        return FetchResponse(body: try Body.decode(Array(bytes.dropLast(64))), signature: Array(bytes.suffix(64)))
    }
}

/// §16: a member's acknowledgement of a verified fetch.
public struct Ack: Hashable, Sendable {
    public struct Body: Hashable, Sendable, BorshCodable {
        public var recipientPk: Hash32
        public var nodePk: Hash32
        public var groupID: Hash32
        public var itemHash: Hash32
        /// Unix ms.
        public var time: UInt64

        public init(recipientPk: Hash32, nodePk: Hash32, groupID: Hash32, itemHash: Hash32, time: UInt64) {
            self.recipientPk = recipientPk; self.nodePk = nodePk; self.groupID = groupID; self.itemHash = itemHash; self.time = time
        }

        public var preimage: Hash32 { Hashing.hash(Domain.ack, borsh) }
        public func borshEncode(into w: inout BorshWriter) { w.fixed(recipientPk); w.fixed(nodePk); w.fixed(groupID); w.fixed(itemHash); w.u64(time) }
        public init(borshFrom r: inout BorshReader) throws {
            recipientPk = try r.hash32(); nodePk = try r.hash32(); groupID = try r.hash32(); itemHash = try r.hash32(); time = try r.u64()
        }
    }

    public let body: Body
    public let signature: [UInt8]

    public init(body: Body, signature: [UInt8]) { self.body = body; self.signature = signature }
    public static func sign(_ body: Body, with groupKey: SigningKey) -> Ack { Ack(body: body, signature: groupKey.sign(body.preimage)) }
    public var isValid: Bool { Signature.verify(signature, hash: body.preimage, publicKey: body.recipientPk) }
    /// The Merkle leaf of an ack batch: `H("convo/leaf" ‖ borsh(Ack))`, sig included.
    public var leaf: Hash32 { Hashing.hash(Domain.leaf, body.borsh + signature) }
    public var wire: [UInt8] { body.borsh + signature }
    public static func fromWire(_ bytes: [UInt8]) throws -> Ack {
        guard bytes.count > 64 else { throw BorshError("ack too short") }
        return Ack(body: try Body.decode(Array(bytes.dropLast(64))), signature: Array(bytes.suffix(64)))
    }
}

/// A batch's log leaf with its proof: what F4 and F5 cite for batch `s`.
public struct BatchProof: Hashable, Sendable, BorshCodable {
    public var root: Hash32
    public var time: UInt64
    public var count: UInt64
    public var proof: MmrProof
    public init(root: Hash32, time: UInt64, count: UInt64, proof: MmrProof) { self.root = root; self.time = time; self.count = count; self.proof = proof }
    public var leaf: Hash32 { MMR.leaf(root: root, time: time, count: count) }
    public func borshEncode(into w: inout BorshWriter) { w.fixed(root); w.u64(time); w.u64(count); proof.borshEncode(into: &w) }
    public init(borshFrom r: inout BorshReader) throws { root = try r.hash32(); time = try r.u64(); count = try r.u64(); proof = try MmrProof(borshFrom: &r) }
    /// The batch index the proof places this leaf at.
    public func index(peaks: [Hash32], size: UInt64) -> Int? { MMR.verify(leaf: leaf, proof: proof, peaks: peaks, size: size) }
}

/// A gap leaf with its path, its index and the tree's leaf count: what
/// F4 and F5 cite inside a batch. The index and count pin the leaf's
/// position (a path alone does not, once odd nodes are promoted), which
/// is what F5 needs; F4 needs only the bounds.
public struct GapProof: Hashable, Sendable, BorshCodable {
    public var leaf: GapTree.Leaf
    public var proof: [Merkle.ProofStep]
    public var index: UInt64
    public var leafCount: UInt64
    public init(leaf: GapTree.Leaf, proof: [Merkle.ProofStep], index: UInt64, leafCount: UInt64) {
        self.leaf = leaf; self.proof = proof; self.index = index; self.leafCount = leafCount
    }
    /// The proof for gap leaf `index` of a batch's items.
    public init(items: [Hash32], index: Int) {
        let leaves = GapTree.leaves(items: items)
        self.init(leaf: leaves[index], proof: GapTree.proof(items: items, leafIndex: index), index: UInt64(index), leafCount: UInt64(leaves.count))
    }
    /// The path verifies at exactly `index` in a tree of `leafCount` leaves.
    public func verifies(root: Hash32) -> Bool {
        Merkle.verify(leaf: leaf.hash, proof: proof, root: root, index: Int(index), count: Int(leafCount), nodeTag: Domain.gapNode)
    }
    public func borshEncode(into w: inout BorshWriter) {
        leaf.borshEncode(into: &w); w.vec(proof) { w, s in s.borshEncode(into: &w) }; w.u64(index); w.u64(leafCount)
    }
    public init(borshFrom r: inout BorshReader) throws {
        leaf = try GapTree.Leaf(borshFrom: &r); proof = try r.vec { try Merkle.ProofStep(borshFrom: &$0) }; index = try r.u64(); leafCount = try r.u64()
    }
}

/// §17: fraud proofs, verified from signatures and Merkle paths by anyone.
public enum FraudProof: Hashable, Sendable {
    /// Receipt for X, a request for X, and a signed response inside the
    /// receipt's window whose `served` does not include X.
    case f1(receipt: Receipt, request: FetchRequest, response: FetchResponse, genesis: [UInt8]?)
    /// Two signed responses to the same request that disagree.
    case f2(first: FetchResponse, second: FetchResponse)
    /// A receipt and a response whose digests for X differ.
    case f3(receipt: Receipt, response: FetchResponse)
    /// A receipt naming batch `s` after `p`; a witnessed checkpoint of the
    /// node's log; batches `s` and `s−1` in it; and the gap in `s` around X.
    case f4(receipt: Receipt, checkpoint: WitnessedCheckpoint, batch: BatchProof, previous: BatchProof, gap: GapProof)
    /// A witnessed checkpoint, batch `s` in it, and a gap leaf past its count.
    case f5(checkpoint: WitnessedCheckpoint, batch: BatchProof, leaf: GapProof)
    /// Two checkpoints the node signed that can't both be its history; the
    /// log's entries through the later one when their `seq`s differ.
    case f6(first: Checkpoint, second: Checkpoint, entries: [LogEntry])

    public enum Rejection: Error, Equatable {
        case badSignature, differentNode, requestMismatch, notAFraud, outsideWindow, unauthorizedNeedsGenesis, badProof, unwitnessed
    }

    public var tag: UInt8 {
        switch self { case .f1: return 1; case .f2: return 2; case .f3: return 3; case .f4: return 4; case .f5: return 5; case .f6: return 6 }
    }

    /// Wire form: a tag byte then the parts, each u32-length-prefixed.
    public var wire: [UInt8] {
        var w = BorshWriter()
        switch self {
        case .f1(let receipt, let request, let response, let genesis):
            w.u8(1); w.vec(receipt.wire); w.vec(request.wire); w.vec(response.wire); w.option(genesis) { w, g in w.vec(g) }
        case .f2(let first, let second): w.u8(2); w.vec(first.wire); w.vec(second.wire)
        case .f3(let receipt, let response): w.u8(3); w.vec(receipt.wire); w.vec(response.wire)
        case .f4(let receipt, let checkpoint, let batch, let previous, let gap):
            w.u8(4); w.vec(receipt.wire); w.vec(checkpoint.borsh); w.vec(batch.borsh); w.vec(previous.borsh); w.vec(gap.borsh)
        case .f5(let checkpoint, let batch, let leaf): w.u8(5); w.vec(checkpoint.borsh); w.vec(batch.borsh); w.vec(leaf.borsh)
        case .f6(let first, let second, let entries):
            w.u8(6); w.vec(first.borsh); w.vec(second.borsh); w.vec(entries) { w, e in e.borshEncode(into: &w) }
        }
        return w.bytes
    }

    public static func fromWire(_ bytes: [UInt8]) throws -> FraudProof {
        var r = BorshReader(bytes)
        let proof: FraudProof
        switch try r.u8() {
        case 1: proof = .f1(receipt: try Receipt.fromWire(try r.vec()), request: try FetchRequest.fromWire(try r.vec()),
                            response: try FetchResponse.fromWire(try r.vec()), genesis: try r.option { try $0.vec() })
        case 2: proof = .f2(first: try FetchResponse.fromWire(try r.vec()), second: try FetchResponse.fromWire(try r.vec()))
        case 3: proof = .f3(receipt: try Receipt.fromWire(try r.vec()), response: try FetchResponse.fromWire(try r.vec()))
        case 4: proof = .f4(receipt: try Receipt.fromWire(try r.vec()), checkpoint: try WitnessedCheckpoint.decode(try r.vec()),
                            batch: try BatchProof.decode(try r.vec()), previous: try BatchProof.decode(try r.vec()),
                            gap: try GapProof.decode(try r.vec()))
        case 5: proof = .f5(checkpoint: try WitnessedCheckpoint.decode(try r.vec()), batch: try BatchProof.decode(try r.vec()),
                            leaf: try GapProof.decode(try r.vec()))
        case 6: proof = .f6(first: try Checkpoint.decode(try r.vec()), second: try Checkpoint.decode(try r.vec()),
                            entries: try r.vec { try LogEntry(borshFrom: &$0) })
        default: throw BorshError("unknown fraud proof")
        }
        try r.finish()
        return proof
    }

    /// The node the proof is against.
    public var nodePk: Hash32 {
        switch self {
        case .f1(let r, _, _, _), .f3(let r, _), .f4(let r, _, _, _, _): return r.body.nodePk
        case .f2(let a, _): return a.body.nodePk
        case .f5(let checkpoint, _, _): return checkpoint.checkpoint.nodePk
        case .f6(let first, _, _): return first.nodePk
        }
    }

    /// The node proven fraudulent, or why the proof does not hold. F4 and F5
    /// need their checkpoint witnessed by `witnessQuorum` independent witnesses.
    public func verify(witnessQuorum: Int = Parameters.Client.witnessQuorum) -> Result<Hash32, Rejection> {
        switch self {
        case .f1(let receipt, let request, let response, let genesis):
            guard receipt.isValid, response.isValid, request.isValid else { return .failure(.badSignature) }
            guard receipt.body.nodePk == response.body.nodePk else { return .failure(.differentNode) }
            guard response.body.requestHash == request.requestHash,
                  case .item(let wanted) = request.body.want, wanted == receipt.body.itemHash else { return .failure(.requestMismatch) }
            guard !response.body.served.contains(where: { $0.0 == wanted }) else { return .failure(.notAFraud) }
            guard receipt.body.received <= response.body.time, response.body.time <= receipt.body.retainUntil else { return .failure(.outsideWindow) }
            if response.body.status == FetchStatus.unauthorized.rawValue {
                // Only a fraud when the requester really is a member.
                guard let genesis, let g = try? Genesis.decode(genesis), g.groupID == receipt.body.groupID,
                      g.members.contains(request.body.requesterPk) else { return .failure(.unauthorizedNeedsGenesis) }
            }
            return .success(receipt.body.nodePk)
        case .f2(let a, let b):
            guard a.isValid, b.isValid else { return .failure(.badSignature) }
            guard a.body.nodePk == b.body.nodePk else { return .failure(.differentNode) }
            guard a.body.requestHash == b.body.requestHash else { return .failure(.requestMismatch) }
            guard a.body.status != b.body.status || a.body.served.map({ $0.0.bytes + $0.1.bytes }) != b.body.served.map({ $0.0.bytes + $0.1.bytes }) else {
                return .failure(.notAFraud)
            }
            return .success(a.body.nodePk)
        case .f3(let receipt, let response):
            guard receipt.isValid, response.isValid else { return .failure(.badSignature) }
            guard receipt.body.nodePk == response.body.nodePk else { return .failure(.differentNode) }
            guard let served = response.body.served.first(where: { $0.0 == receipt.body.itemHash }) else { return .failure(.requestMismatch) }
            guard served.1 != receipt.body.contentDigest else { return .failure(.notAFraud) }
            return .success(receipt.body.nodePk)
        case .f4(let receipt, let witnessed, let batch, let previous, let gap):
            guard receipt.isValid else { return .failure(.badSignature) }
            let log = witnessed.checkpoint
            guard log.nodePk == receipt.body.nodePk else { return .failure(.differentNode) }
            guard witnessed.isPublished(quorum: witnessQuorum) else { return .failure(.unwitnessed) }
            let s = receipt.body.batchSeq
            guard s > 0 || previous.root == receipt.body.batchPrev else { return .failure(.badProof) }
            guard batch.index(peaks: log.mmrPeaks, size: log.size) == Int(s) else { return .failure(.badProof) }
            if s > 0 {
                guard previous.index(peaks: log.mmrPeaks, size: log.size) == Int(s - 1), previous.root == receipt.body.batchPrev else { return .failure(.badProof) }
            }
            guard gap.leaf.contains(strictly: receipt.body.itemHash), gap.verifies(root: batch.root) else { return .failure(.notAFraud) }
            return .success(receipt.body.nodePk)
        case .f5(let witnessed, let batch, let leaf):
            let log = witnessed.checkpoint
            guard witnessed.isPublished(quorum: witnessQuorum) else { return .failure(.unwitnessed) }
            guard batch.index(peaks: log.mmrPeaks, size: log.size) != nil else { return .failure(.badProof) }
            guard leaf.verifies(root: batch.root) else { return .failure(.badProof) }
            // An honest batch of `count` items has `count + 1` gap leaves.
            guard leaf.index >= batch.count + 1 else { return .failure(.notAFraud) }
            return .success(log.nodePk)
        case .f6(let first, let second, let entries):
            guard first.isSigned, second.isSigned else { return .failure(.badSignature) }
            guard first.nodePk == second.nodePk else { return .failure(.differentNode) }
            guard Checkpoint.equivocate(first, second, entries: entries) else { return .failure(.notAFraud) }
            return .success(first.nodePk)
        }
    }
}
