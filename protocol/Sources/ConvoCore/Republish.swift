import ConvoFoundation

/// §9.4: a parent-group message carried into a child with its inclusion
/// proof against a committed parent attestation's content root. Travels
/// as the (encrypted) payload of an ordinary `kind = 2` child message.
/// The cited attestation rides along, so a child member who cannot reach
/// the parent's nodes can still verify.
public struct Republish: Hashable, Sendable, BorshCodable {
    public var parentGroupID: Hash32
    /// A committed parent attestation, which carries `content_root`.
    public var source: CommitmentRef
    public var attestation: Attestation
    public var attestationSig: [UInt8]
    public var original: Message
    public var originalSig: [UInt8]
    public var inclusionProof: [Merkle.ProofStep]

    public init(parentGroupID: Hash32, source: CommitmentRef, attestation: SignedAttestation, original: SignedMessage, inclusionProof: [Merkle.ProofStep]) {
        self.parentGroupID = parentGroupID
        self.source = source
        self.attestation = attestation.attestation
        self.attestationSig = attestation.signature
        self.original = original.message
        self.originalSig = original.signature
        self.inclusionProof = inclusionProof
    }

    public var signedOriginal: SignedMessage { SignedMessage(message: original, signature: originalSig) }
    public var signedAttestation: SignedAttestation { SignedAttestation(attestation: attestation, signature: attestationSig) }

    /// §9.4 verification: the source resolves to the attestation, which a
    /// parent member signed over `parentGroupID`; the original's signature
    /// verifies against the parent's member; the proof reaches the
    /// attestation's content root. The source resolves against its own
    /// witnessed checkpoint.
    public func verify(parentMembers: [Hash32], witnessQuorum: Int = Parameters.Client.witnessQuorum) -> Bool {
        verify(parentMembers: parentMembers) { $0.resolves(witnessQuorum: witnessQuorum) }
    }

    /// The same with the caller resolving the source (against a later
    /// checkpoint of the node's log, say).
    public func verify(parentMembers: [Hash32], resolves: (CommitmentRef) -> Bool) -> Bool {
        guard source.itemHash == attestation.itemHash, attestation.groupID == parentGroupID,
              Int(attestation.signerIdx) < parentMembers.count,
              signedAttestation.verify(signer: parentMembers[Int(attestation.signerIdx)]),
              resolves(source),
              original.groupID == parentGroupID,
              Int(original.authorIdx) < parentMembers.count,
              signedOriginal.verify(author: parentMembers[Int(original.authorIdx)]) else { return false }
        return Merkle.verify(leaf: signedOriginal.leaf, proof: inclusionProof, root: attestation.contentRoot)
    }

    public func borshEncode(into w: inout BorshWriter) {
        w.fixed(parentGroupID); source.borshEncode(into: &w); attestation.borshEncode(into: &w); w.fixed(attestationSig)
        original.borshEncode(into: &w); w.fixed(originalSig)
        w.vec(inclusionProof) { w, s in s.borshEncode(into: &w) }
    }

    public init(borshFrom r: inout BorshReader) throws {
        parentGroupID = try r.hash32(); source = try CommitmentRef(borshFrom: &r); attestation = try Attestation(borshFrom: &r)
        attestationSig = try r.fixed(64); original = try Message(borshFrom: &r)
        originalSig = try r.fixed(64); inclusionProof = try r.vec { try Merkle.ProofStep(borshFrom: &$0) }
    }
}

/// §12: a request for what a requester is missing, signed by its group key.
public struct SyncRequest: Hashable, Sendable {
    public struct Body: Hashable, Sendable, BorshCodable {
        public var groupID: Hash32
        /// The latest head the requester holds full data for (zeros: none).
        public var haveHead: Hash32
        public var wantHead: Hash32
        public var missing: [Hash32]?
        public var nonce: [UInt8]
        /// Unix ms.
        public var time: UInt64
        public var requesterIdx: UInt8

        public init(groupID: Hash32, haveHead: Hash32, wantHead: Hash32, missing: [Hash32]?, nonce: [UInt8], time: UInt64, requesterIdx: UInt8) {
            precondition(nonce.count == 16)
            self.groupID = groupID; self.haveHead = haveHead; self.wantHead = wantHead
            self.missing = missing; self.nonce = nonce; self.time = time; self.requesterIdx = requesterIdx
        }

        public var preimage: Hash32 { Hashing.hash(Domain.sync, borsh) }

        public func borshEncode(into w: inout BorshWriter) {
            w.fixed(groupID); w.fixed(haveHead); w.fixed(wantHead)
            w.option(missing) { w, m in w.vec(m) { w, h in w.fixed(h) } }
            w.fixed(nonce); w.u64(time); w.u8(requesterIdx)
        }

        public init(borshFrom r: inout BorshReader) throws {
            groupID = try r.hash32(); haveHead = try r.hash32(); wantHead = try r.hash32()
            missing = try r.option { try $0.vec { try $0.hash32() } }
            nonce = try r.fixed(16); time = try r.u64(); requesterIdx = try r.u8()
        }
    }

    public let body: Body
    public let signature: [UInt8]

    public init(body: Body, signature: [UInt8]) { self.body = body; self.signature = signature }

    public static func sign(_ body: Body, with groupKey: SigningKey) -> SyncRequest {
        SyncRequest(body: body, signature: groupKey.sign(body.preimage))
    }

    public func verify(requester: Hash32) -> Bool { Signature.verify(signature, hash: body.preimage, publicKey: requester) }

    /// Wire form: borsh(body) ‖ sig.
    public var wire: [UInt8] { body.borsh + signature }

    public static func fromWire(_ bytes: [UInt8]) throws -> SyncRequest {
        guard bytes.count > 64 else { throw BorshError("sync request too short") }
        return SyncRequest(body: try Body.decode(Array(bytes.dropLast(64))), signature: Array(bytes.suffix(64)))
    }
}
