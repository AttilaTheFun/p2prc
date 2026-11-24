import ConvoCore
import ConvoFoundation
// Not on Android: Isomer's Foundation stands in for the SDK's there, whose
// FoundationNetworking is still importable but would link beside it.
#if canImport(FoundationNetworking) && !os(Android)
import FoundationNetworking
#endif

/// How requests reach a node: HTTP in the app, a direct call in tests.
public protocol NodeTransport: Sendable {
    func request(_ method: String, _ path: String, body: [UInt8], contentType: String, headers: [String: String]) async throws -> (status: Int, body: [UInt8])
}

extension NodeTransport {
    public func request(_ method: String, _ path: String, body: [UInt8], contentType: String) async throws -> (status: Int, body: [UInt8]) {
        try await request(method, path, body: body, contentType: contentType, headers: [:])
    }
}

#if !os(WASI) && !os(Android)
/// URLSession-backed; the browser and Android builds route requests through
/// their hosts instead (WASI has no networking of its own, and Isomer's
/// Foundation on Android has no URLSession).
public struct HTTPNodeTransport: NodeTransport {
    public let base: URL
    public var timeout: TimeInterval = Parameters.Client.receiptTimeoutSeconds
    public init(base: URL) { self.base = base }

    public func request(_ method: String, _ path: String, body: [UInt8], contentType: String, headers: [String: String]) async throws -> (status: Int, body: [UInt8]) {
        var request = URLRequest(url: URL(string: base.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path)!)
        request.httpMethod = method
        request.timeoutInterval = timeout
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        if method == "POST" {
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
            request.httpBody = Data(body)
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw NodeClient.Failure.badResponse }
        return (http.statusCode, Array(data))
    }
}
#endif

/// The client side of the node API: posts items for receipts, fetches with
/// signed requests, verifies what comes back, produces acks, and reads
/// the node's commitments and log. Every method returns the signed
/// objects so the caller can keep them as proof.
public struct NodeClient: Sendable {
    public let transport: any NodeTransport
    #if !os(WASI) && !os(Android)
    public init(base: URL) { transport = HTTPNodeTransport(base: base) }
    #endif
    public init(transport: any NodeTransport) { self.transport = transport }

    public enum Failure: Error, Equatable {
        case http(Int), noReceipt, digestMismatch, badResponse, badSignature
    }

    private func post(_ path: String, body: [UInt8], contentType: String = "application/octet-stream", headers: [String: String] = [:]) async throws -> [UInt8] {
        let (status, data) = try await transport.request("POST", path, body: body, contentType: contentType, headers: headers)
        guard (200..<300).contains(status) else { throw Failure.http(status) }
        return data
    }

    /// §19: who signs a member-only GET, and when (unix ms; within
    /// `NodeAPI.authWindowMs` of the node's clock).
    public struct GetAuth: Sendable {
        public let key: SigningKey
        public let time: UInt64
        public init(key: SigningKey, time: UInt64 = Parameters.nowMs()) { self.key = key; self.time = time }
        func headers(for path: String) -> [String: String] { [NodeAPI.authHeader: NodeAPI.getAuth(key: key, pathAndQuery: path, time: time)] }
    }

    public func get(_ path: String, auth: GetAuth? = nil) async throws -> [UInt8] {
        let (status, data) = try await transport.request("GET", path, body: [], contentType: "", headers: auth?.headers(for: path) ?? [:])
        guard (200..<300).contains(status) else { throw Failure.http(status) }
        return data
    }

    public func info() async throws -> NodeInfo {
        try JSONDecoder().decode(NodeInfo.self, from: Data(try await get(NodeAPI.info)))
    }

    /// Checks a receipt against what was sent (§14): the digest must be
    /// over the exact bytes, and the node must be the one expected.
    private func check(_ receiptBytes: [UInt8], itemHash: Hash32, expectedDigest: Hash32, expectedNode: PublicKey?) throws -> Receipt {
        guard let receipt = try? Receipt.fromWire(receiptBytes), receipt.isValid else { throw Failure.noReceipt }
        guard receipt.body.itemHash == itemHash, receipt.body.contentDigest == expectedDigest else { throw Failure.digestMismatch }
        if let expectedNode, receipt.body.nodePk != expectedNode { throw Failure.badSignature }
        return receipt
    }

    /// Posts an item and returns the verified receipt.
    public func send(_ bytes: [UInt8], kind: NodeAPI.ItemKind, groupID: Hash32, itemHash: Hash32, expectedNode: PublicKey?) async throws -> Receipt {
        let data = try await post(NodeAPI.item(groupID, kind: kind), body: bytes)
        return try check(data, itemHash: itemHash, expectedDigest: Hashing.sha256(bytes), expectedNode: expectedNode)
    }

    public func sendBlob(_ bytes: [UInt8], groupID: Hash32, expectedNode: PublicKey?) async throws -> Receipt {
        let digest = Hashing.sha256(bytes)
        let data = try await post(NodeAPI.blob(groupID, digest), body: bytes)
        return try check(data, itemHash: digest, expectedDigest: digest, expectedNode: expectedNode)
    }

    public func blob(groupID: Hash32, hash: Hash32) async throws -> [UInt8] { try await get(NodeAPI.blob(groupID, hash)) }

    /// A signed fetch; the response is verified and each served item's
    /// digest checked before it is returned. Items whose digest does not
    /// match are dropped. A response from before the request (§15) is no
    /// response.
    public func fetch(_ request: FetchRequest) async throws -> (FetchResponse, [(hash: Hash32, bytes: [UInt8])]) {
        let data = try await post(NodeAPI.fetch(request.body.groupID), body: request.wire)
        let reply = try FetchReply.fromWire(data)
        guard reply.response.isValid, reply.response.body.requestHash == request.requestHash,
              reply.response.body.time >= request.body.time else { throw Failure.badResponse }
        var items: [(Hash32, [UInt8])] = []
        for (i, bytes) in reply.items.enumerated() where i < reply.response.body.served.count {
            let (hash, digest) = reply.response.body.served[i]
            if Hashing.sha256(bytes) == digest { items.append((hash, bytes)) }
        }
        return (reply.response, items)
    }

    /// Registers (or, with an empty handle, withdraws) a wake with this host.
    public func registerWake(_ registration: WakeRegistration) async throws {
        _ = try await post(NodeAPI.wake(registration.body.groupID), body: registration.wire)
    }

    public func ack(_ ack: Ack) async throws {
        _ = try await post(NodeAPI.ack(ack.body.groupID), body: ack.wire)
    }

    public func attestations(groupID: Hash32, auth: GetAuth? = nil) async throws -> [AttestationRecord] {
        try JSONDecoder().decode([AttestationRecord].self, from: Data(try await get(NodeAPI.attestations(groupID), auth: auth)))
    }

    /// The node's `CommitmentRef` for an item it committed, or nil (404).
    public func commitment(itemHash: Hash32, auth: GetAuth? = nil) async throws -> CommitmentRef? {
        let path = NodeAPI.commitment(itemHash)
        let (status, data) = try await transport.request("GET", path, body: [], contentType: "", headers: auth?.headers(for: path) ?? [:])
        guard status != 404 else { return nil }
        guard (200..<300).contains(status) else { throw Failure.http(status) }
        return try CommitmentRef.decode(data)
    }

    /// The newest witnessed checkpoint the node holds for a log (its own or
    /// one it witnessed), or nil (404).
    public func checkpoint(_ nodePk: Hash32) async throws -> WitnessedCheckpoint? {
        let (status, data) = try await transport.request("GET", NodeAPI.checkpoint(nodePk), body: [], contentType: "", headers: [:])
        guard status != 404 else { return nil }
        guard (200..<300).contains(status) else { throw Failure.http(status) }
        return try WitnessedCheckpoint.fromWire(data)
    }

    /// What a witness answered (§11).
    public enum WitnessAnswer: Sendable, Equatable {
        case cosigned(Cosignature)
        /// 409: how many batches of the log the witness holds, and its
        /// newest checkpoint of it.
        case conflict(size: UInt64, latest: WitnessedCheckpoint?)
    }

    /// A 409's body: `u64 size ‖ Option<WitnessedCheckpoint>`.
    public static func witnessConflict(size: UInt64, latest: WitnessedCheckpoint?) -> [UInt8] {
        var w = BorshWriter(); w.u64(size); w.option(latest) { w, c in c.borshEncode(into: &w) }
        return w.bytes
    }

    public func witness(_ request: WitnessRequest) async throws -> WitnessAnswer {
        let (status, data) = try await transport.request("POST", NodeAPI.witness, body: request.wire, contentType: "application/octet-stream", headers: [:])
        if status == 409 {
            var r = BorshReader(data)
            let size = try r.u64()
            let latest = try r.option { try WitnessedCheckpoint(borshFrom: &$0) }
            return .conflict(size: size, latest: latest)
        }
        guard (200..<300).contains(status) else { throw Failure.http(status) }
        let cosignature = try Cosignature.decode(data)
        guard cosignature.verifies(request.checkpoint) else { throw Failure.badSignature }
        return .cosigned(cosignature)
    }

    public func batch(_ nodePk: Hash32, seq: UInt64) async throws -> CommitmentBatch {
        try CommitmentBatch.fromWire(try await get(NodeAPI.batch(nodePk, seq: seq)))
    }

    /// Every batch of the log the node holds, as log entries, in sequence.
    public func batchLeaves(_ nodePk: Hash32) async throws -> [BatchLeaf] {
        try JSONDecoder().decode([BatchLeaf].self, from: Data(try await get(NodeAPI.batches(nodePk))))
    }

    public func batchProof(_ nodePk: Hash32, seq: UInt64) async throws -> MmrProof {
        try MmrProof.decode(try await get(NodeAPI.batchProof(nodePk, seq: seq)))
    }

    public func pushBatch(_ batch: CommitmentBatch) async throws {
        _ = try await post(NodeAPI.batches(batch.nodePk), body: batch.wire)
    }

    public func publishGenesis(_ record: GenesisRecord) async throws {
        _ = try await post(NodeAPI.genesis(record.genesis.groupID), body: record.wire)
    }

    public func genesis(groupID: Hash32, auth: GetAuth? = nil) async throws -> GenesisRecord {
        try GenesisRecord.fromWire(try await get(NodeAPI.genesis(groupID), auth: auth))
    }

    /// Gossips a fraud proof (§17).
    public func submitFraud(_ proof: FraudProof) async throws {
        _ = try await post(NodeAPI.fraud, body: proof.wire)
    }

    /// The fraud proofs the node holds against `nodePk`, each verified.
    public func fraudProofs(against nodePk: Hash32) async throws -> [FraudProof] {
        let hex = try JSONDecoder().decode([String].self, from: Data(try await get(NodeAPI.fraud(against: nodePk))))
        return hex.compactMap { [UInt8](hex: $0) }.compactMap { try? FraudProof.fromWire($0) }
            .filter { (try? $0.verify().get()) == nodePk }
    }

    /// Publishes an identity record (§13.2).
    public func publishIdentity(_ record: IdentityRecord) async throws -> Receipt {
        let data = try await post(NodeAPI.identity(record.idPk), body: record.wire)
        let digest = Hashing.sha256(record.wire)
        return try check(data, itemHash: digest, expectedDigest: digest, expectedNode: nil)
    }

    /// The newest identity record the node holds, verified, or nil (404).
    public func identity(_ idPk: Hash32) async throws -> IdentityRecord? {
        let (status, data) = try await transport.request("GET", NodeAPI.identity(idPk), body: [], contentType: "", headers: [:])
        guard status != 404 else { return nil }
        guard (200..<300).contains(status) else { throw Failure.http(status) }
        let record = try IdentityRecord.fromWire(data)
        guard record.isValid, record.idPk == idPk else { throw Failure.badSignature }
        return record
    }

    public func publishKeyPackage(identity: Hash32, bytes: [UInt8]) async throws -> Receipt {
        let data = try await post(NodeAPI.keyPackage(identity), body: bytes)
        return try check(data, itemHash: Hashing.sha256(bytes), expectedDigest: Hashing.sha256(bytes), expectedNode: nil)
    }
    public func keyPackage(identity: Hash32) async throws -> [UInt8] { try await get(NodeAPI.keyPackage(identity)) }

    // MARK: Part III

    public func ice(for client: String) async throws -> ICEAnswer {
        try JSONDecoder().decode(ICEAnswer.self, from: Data(try await get(NodeAPI.ice + "?for=" + client)))
    }

    public func drop(_ bytes: [UInt8], box: String) async throws {
        _ = try await post(NodeAPI.rendezvous(box), body: Array(Data(bytes).base64EncodedString().utf8), contentType: "text/plain")
    }

    public func poll(box: String) async throws -> [UInt8]? {
        let (status, data) = try await transport.request("GET", NodeAPI.rendezvous(box), body: [], contentType: "", headers: [:])
        guard status != 404 else { return nil }
        guard (200..<300).contains(status) else { throw Failure.http(status) }
        guard let bytes = Data(base64Encoded: String(decoding: data, as: UTF8.self)) else { throw Failure.badResponse }
        return Array(bytes)
    }
}

public struct ICEServer: Codable, Equatable, Sendable {
    public var urls: [String]
    public var username: String?
    public var credential: String?
    public init(urls: [String], username: String? = nil, credential: String? = nil) {
        self.urls = urls; self.username = username; self.credential = credential
    }
}

public struct ICEAnswer: Codable, Equatable, Sendable {
    public var iceServers: [ICEServer]
    public var ttl: Int
    public init(iceServers: [ICEServer], ttl: Int) { self.iceServers = iceServers; self.ttl = ttl }
}
