import ConvoCore
import ConvoNet
import ConvoFoundation

/// The reference node (§13–17 and Part III): a mailbox with signed
/// receipts naming the batch each item will be committed in, signed
/// fetch responses served to members only, acks, KeyPackages, identity
/// records, blobs, geneses, commitment proofs, a witness for other nodes'
/// logs, fraud-proof gossip, and the discovery, rendezvous and ICE
/// endpoints members use to find each other. One instance serves one
/// `PosixHTTPServer`.
public final class ConvoNodeServer: @unchecked Sendable {
    public static let version = "2.0"

    public struct Configuration: Sendable {
        public var id: String
        public var publicURL: String?
        public var site: String?
        public var seeds: [String]
        public var limit: Int
        public var stateDirectory: String?
        /// Who runs the node (§24); the node's own key when unset.
        public var operatorPk: PublicKey?
        public var deliveryWindowMs: UInt64
        public var retentionMs: UInt64
        public var maxItemBytes: Int
        public var maxBlobBytes: Int
        /// All the blobs held, at most (bytes); nil for no limit. A host
        /// with little memory (a Worker's 128 MB) sets it.
        public var maxBlobStoreBytes: Int?
        /// Everything held for others (Mailbox.storedBytes), at most; nil for
        /// no limit. Past it the node takes nothing more until retention
        /// frees room, but keeps serving and keeping its own log.
        public var maxStoredBytes: Int?

        public init(id: String, publicURL: String? = nil, site: String? = nil, seeds: [String] = [], limit: Int = 20,
                    stateDirectory: String? = nil, operatorPk: PublicKey? = nil,
                    deliveryWindowMs: UInt64 = Parameters.Node.deliveryWindowMs,
                    retentionMs: UInt64 = Parameters.Node.minRetentionMs,
                    maxItemBytes: Int = 64 * 1024, maxBlobBytes: Int = 16 * 1024 * 1024, maxBlobStoreBytes: Int? = nil,
                    maxStoredBytes: Int? = nil) {
            self.id = id; self.publicURL = publicURL; self.site = site; self.seeds = seeds; self.limit = limit
            self.stateDirectory = stateDirectory; self.operatorPk = operatorPk; self.deliveryWindowMs = deliveryWindowMs
            self.retentionMs = retentionMs; self.maxItemBytes = maxItemBytes; self.maxBlobBytes = maxBlobBytes
            self.maxBlobStoreBytes = maxBlobStoreBytes; self.maxStoredBytes = maxStoredBytes
        }
    }

    public typealias Fetch = @Sendable (_ method: String, _ url: String, _ body: Data?) -> (Int, Data?)

    public let configuration: Configuration
    public let key: SigningKey
    public let mailbox: Mailbox
    public let ice: any ICESource
    public var log: (@Sendable (String) -> Void)?
    /// Unix seconds; `nowMs` is the same clock in milliseconds.
    public var clock: @Sendable () -> Double = { Date().timeIntervalSince1970 }
    /// Calls another node or a relay and waits for the answer (discovery and
    /// health checks). A host without blocking calls (a Worker) leaves it
    /// unanswered and drives discovery itself.
    public var fetch: Fetch
    /// Sends a call whose answer nobody waits for (wakes, fraud gossip). Nil:
    /// `fetch` in place. Hosts pass their own: a queue, or a Worker's outbox.
    public var send: (@Sendable (_ method: String, _ url: String, _ body: Data?) -> Void)?
    /// The batch receipts name and the root before it (§14); the
    /// mailbox's by default.
    public var openBatch: @Sendable () -> (seq: UInt64, prev: Hash32)

    public func nowMs() -> UInt64 { UInt64(max(0, clock()) * 1000) }

    /// Whether this instance may write the node's state (`StateLease`); a
    /// write once it may not is refused, and `onLeaseLost` runs.
    public var mayWrite: @Sendable () -> Bool = { true }
    public var onLeaseLost: (@Sendable () -> Void)?

    public var nodePk: PublicKey { key.publicKey }

    private let lock = NSLock()
    private var directory: ServerDirectory
    private var lastAdvertised: Double = 0
    private var pendingSeeds: [String]

    // Rendezvous boxes (§20).
    private var boxes: [String: [(blob: String, at: Double)]] = [:]
    private var boxOrder: [String] = []
    /// What the boxes hold, in bytes, at most `maxBoxBytes`.
    private var boxBytes = 0
    public static let maxBoxBytes = 8 * 1024 * 1024
    public static let blobLifetime: Double = Parameters.Node.rendezvousBoxLifetimeSeconds
    public static let rendezvousMaxBytes = 16 * 1024
    public static let boxMaxBlobs = 32
    public static let maxBoxes = 4096
    public static let advertiseInterval: Double = 1800

    /// Members' wake registrations (§19.1) and the calls out to their relays,
    /// made through `send`.
    public let wakes: WakeRegistry
    private let wakeLimiter = RateLimiter(perMinute: 60, burst: 20)

    private let itemLimiter = RateLimiter(perMinute: 600, burst: 120)
    private let fetchLimiter = RateLimiter(perMinute: 600, burst: 120)
    private let dropLimiter = RateLimiter(perMinute: 60, burst: 30)
    private let pollLimiter = RateLimiter(perMinute: 240, burst: 60)
    private let advertiseLimiter = RateLimiter(perMinute: 6, burst: 6)
    private let iceLimiter = RateLimiter(perMinute: 30, burst: 10)
    private let witnessLimiter = RateLimiter(perMinute: 120, burst: 30)
    private let fraudLimiter = RateLimiter(perMinute: 30, burst: 10)
    private let blobLimiter = RateLimiter(perMinute: 20, burst: 10)
    private let genesisLimiter = RateLimiter(perMinute: 30, burst: 10)
    private let batchLimiter = RateLimiter(perMinute: 60, burst: 20)
    /// New identities and key packages: a client publishes its own a few times.
    private let identityLimiter = RateLimiter(perMinute: 30, burst: 15)

    public init(configuration: Configuration, key: SigningKey, ice: any ICESource, mailbox: Mailbox? = nil, fetch: Fetch? = nil) {
        self.configuration = configuration
        self.key = key
        self.ice = ice
        let box = mailbox ?? Mailbox(directory: configuration.stateDirectory.map { $0 + "/mailbox" })
        self.mailbox = box
        self.wakes = WakeRegistry(directory: configuration.stateDirectory)
        self.openBatch = { box.openBatch }
        self.fetch = fetch ?? { _, _, _ in (0, nil) }
        var directory = ServerDirectory(limit: configuration.limit)
        if let dir = configuration.stateDirectory,
           let saved = try? String(contentsOfFile: dir + "/servers.json", encoding: .utf8) {
            directory = ServerDirectory.decode(saved, limit: configuration.limit)
        }
        if let own = configuration.publicURL.flatMap(ServerDirectory.normalize) { directory.remove(own) }
        self.directory = directory
        self.pendingSeeds = configuration.seeds
    }

    /// Loads the node key from `<stateDirectory>/node.key` or makes one and
    /// saves it there, so the node's identity survives restarts.
    public static func loadOrCreateKey(stateDirectory: String?) -> SigningKey {
        guard let stateDirectory else { return SigningKey.random() }
        let path = stateDirectory + "/node.key"
        if let data = FileManager.default.contents(atPath: path), data.count == 32, let key = try? SigningKey(seed: Array(data)) {
            return key
        }
        let key = SigningKey.random()
        try? StateFiles.write(Data(key.seed), to: path)
        StateFiles.restrict(path)
        return key
    }

    // MARK: routing

    public func respond(to request: HTTPRequest) -> HTTPResponse {
        let (path, query) = Self.split(request.path)
        let ip = Self.address(of: request.peer)
        let now = clock()
        let parts = path.split(separator: "/").map(String.init)

        // CORS preflight: browsers ask before any POST whose body is not a
        // form type (every byte route here). The allow headers ride on every
        // response, so the answer is just "yes, ask".
        if request.method == "OPTIONS" { return HTTPResponse(status: 204, body: Data()) }
        // Another instance of this node holds the state: answer nothing that
        // writes, so the log keeps one author (§28).
        if request.method == "POST", !mayWrite() {
            onLeaseLost?()
            return HTTPResponse(status: 503, text: "this instance no longer holds the node's state")
        }

        switch (request.method, path) {
        case ("GET", NodeAPI.health), ("GET", "/healthcheck"):
            return Self.json(healthReport(now: now))
        case ("GET", NodeAPI.info):
            return Self.json(info(now: now))
        case ("GET", "/servers"):
            return Self.json(serverList())
        case ("POST", "/servers"):
            return advertiseReceived(request, ip: ip, now: now)
        case ("GET", "/ice"):
            if let wait = iceLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            let client = query["for"] ?? "anon"
            let (servers, ttl) = ice.iceServers(for: client, now: Date(timeIntervalSince1970: now))
            guard !servers.isEmpty else { return HTTPResponse(status: 503, text: "no ice servers configured") }
            return Self.json(ICEAnswer(iceServers: servers, ttl: ttl))
        case ("POST", NodeAPI.witness):
            if let wait = witnessLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            return witness(request)
        case ("POST", NodeAPI.fraud):
            if let wait = fraudLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            guard let proof = try? FraudProof.fromWire(Array(request.body)) else { return HTTPResponse(status: 400, text: "bad proof") }
            guard accept(proof) else { return HTTPResponse(status: 400, text: "proof does not verify") }
            return HTTPResponse(status: 202, text: "accepted")
        case ("GET", NodeAPI.fraud):
            guard let node = query["node"].flatMap({ Hash32(hex: $0) }) else { return HTTPResponse(status: 400, text: "?node=<pk> required") }
            return Self.json(mailbox.fraudProofs(against: node).map(\.hex))
        default:
            break
        }

        if parts.count == 2, parts[0] == "rendezvous" { return rendezvous(request, box: parts[1], ip: ip, now: now) }
        guard parts.count >= 2, parts[0] == "v1" else { return HTTPResponse(status: 404, text: "not found") }

        switch parts[1] {
        case "keypackages":
            guard parts.count == 3, let identity = Hash32(hex: parts[2]) else { return HTTPResponse(status: 400, text: "bad identity") }
            if request.method == "POST" {
                if let wait = identityLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
                guard !request.body.isEmpty, request.body.count <= configuration.maxItemBytes else { return HTTPResponse(status: 413, text: "key package size") }
                guard hasRoom(for: request.body.count) else { return Self.full }
                let bytes = Array(request.body)
                let digest = Hashing.sha256(bytes)
                if let existing = mailbox.item(hash: digest) { return HTTPResponse(contentType: "application/octet-stream", body: Data(existing.stored.receipt.wire)) }
                do { try mailbox.storeKeyPackage(bytes, identity: identity) } catch { return HTTPResponse(status: 503, text: "not stored") }
                let receipt = makeReceipt(groupID: NodeAPI.identityGroup, itemHash: digest, digest: digest)
                return HTTPResponse(contentType: "application/octet-stream", body: Data(receipt.wire))
            }
            guard let bytes = mailbox.keyPackage(identity: identity) else { return HTTPResponse(status: 404, text: "no key package") }
            return HTTPResponse(contentType: "application/octet-stream", body: Data(bytes))
        case "groups":
            guard parts.count >= 4, let groupID = Hash32(hex: parts[2]) else { return HTTPResponse(status: 400, text: "bad group id") }
            return group(groupID, request: request, tail: Array(parts[3...]), ip: ip, now: now)
        case "identities":
            guard parts.count == 3, let idPk = Hash32(hex: parts[2]) else { return HTTPResponse(status: 400, text: "bad identity") }
            if request.method == "POST" {
                if let wait = identityLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
                guard request.body.count <= configuration.maxItemBytes, let record = try? IdentityRecord.fromWire(Array(request.body)),
                      record.isValid, record.idPk == idPk else { return HTTPResponse(status: 400, text: "bad identity record") }
                guard mailbox.identity(idPk) != nil || hasRoom(for: request.body.count) else { return Self.full }
                let stored: Bool
                do { stored = try mailbox.storeIdentity(record) } catch { return HTTPResponse(status: 503, text: "not stored") }
                guard stored || mailbox.identity(idPk) == record else { return HTTPResponse(status: 409, text: "older than the record held") }
                let digest = Hashing.sha256(record.wire)
                let receipt = makeReceipt(groupID: NodeAPI.identityGroup, itemHash: digest, digest: digest)
                return HTTPResponse(contentType: "application/octet-stream", body: Data(receipt.wire))
            }
            guard let record = mailbox.identity(idPk) else { return HTTPResponse(status: 404, text: "no identity record") }
            return HTTPResponse(contentType: "application/octet-stream", body: Data(record.wire))
        case "items":
            guard parts.count == 4, parts[3] == "commitment", let hash = Hash32(hex: parts[2]) else { return HTTPResponse(status: 400, text: "bad item") }
            guard let ref = mailbox.commitment(of: hash) else { return HTTPResponse(status: 404, text: "not committed by this node") }
            // Members of the item's group; identity-scoped items (KeyPackages,
            // group zero) have no roster, so any valid signer may ask.
            let owner = mailbox.item(hash: hash)?.groupID
            let allowed: (PublicKey) -> Bool = { pk in
                guard let owner else { return false }
                if owner == NodeAPI.identityGroup { return true }
                return self.mailbox.genesis(groupID: owner)?.genesis.members.contains(pk) ?? false
            }
            guard authorizedGet(request, allowed: allowed) else { return Self.unauthorizedGet }
            return HTTPResponse(contentType: "application/octet-stream", body: Data(ref.borsh))
        case "notary":
            guard parts.count >= 4, let pk = Hash32(hex: parts[2]) else { return HTTPResponse(status: 400, text: "bad notary path") }
            if parts.count == 4, parts[3] == "checkpoint", request.method == "GET" {
                guard let checkpoint = mailbox.latestCheckpoint(of: pk, own: nodePk) else { return HTTPResponse(status: 404, text: "no checkpoint of that log here") }
                return HTTPResponse(contentType: "application/octet-stream", body: Data(checkpoint.wire))
            }
            guard parts[3] == "batches" else { return HTTPResponse(status: 404, text: "not found") }
            if parts.count == 4, request.method == "GET" {
                // The log's entries, so anyone can rebuild it at any size (A.4).
                let entries = pk == nodePk ? mailbox.logEntries : mailbox.witnessedEntries(of: pk)
                return Self.json(entries.enumerated().map { BatchLeaf(seq: UInt64($0.offset), root: $0.element.root.hex, time: $0.element.time, count: $0.element.count) })
            }
            if parts.count == 4, request.method == "POST" {
                if let wait = batchLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
                // Only a log this node witnesses (§11) or a fellow home of a group held here (§13).
                guard pk != nodePk, mailbox.latestCheckpoint(of: pk, own: nodePk) != nil || mailbox.isCoHome(pk) else {
                    return HTTPResponse(status: 403, text: "not a node this one witnesses or shares a group with")
                }
                guard request.body.count <= configuration.maxBlobBytes else { return HTTPResponse(status: 413, text: "batch size") }
                guard hasRoom(for: request.body.count) else { return Self.full }
                guard let batch = try? CommitmentBatch.fromWire(Array(request.body)), batch.nodePk == pk, batch.isValid else { return HTTPResponse(status: 400, text: "bad batch") }
                do { try mailbox.storeForeign(batch, at: nowMs()) } catch { return HTTPResponse(status: 503, text: "not stored") }
                return HTTPResponse(status: 204, body: Data())
            }
            guard parts.count >= 5, let seq = UInt64(parts[4]) else { return HTTPResponse(status: 400, text: "bad sequence") }
            if parts.count == 5 {
                if pk == nodePk, let posted = mailbox.postedBatch(seq: seq) { return HTTPResponse(contentType: "application/octet-stream", body: Data(posted.batch.wire)) }
                if let batch = mailbox.batch(node: pk, seq: seq) { return HTTPResponse(contentType: "application/octet-stream", body: Data(batch.wire)) }
                return HTTPResponse(status: 404, text: "no such batch here")
            }
            if parts.count == 6, parts[5] == "proof", pk == nodePk {
                // Against the newest witnessed checkpoint, which may trail the log.
                guard let checkpoint = mailbox.checkpoint, seq <= checkpoint.checkpoint.seq else { return HTTPResponse(status: 404, text: "not checkpointed yet") }
                let leaves = mailbox.logEntries.prefix(Int(checkpoint.checkpoint.size)).map(\.leaf)
                guard let proof = MMR(leaves: Array(leaves)).proof(index: Int(seq)) else { return HTTPResponse(status: 404, text: "no such batch") }
                return HTTPResponse(contentType: "application/octet-stream", body: Data(proof.borsh))
            }
            return HTTPResponse(status: 404, text: "not found")
        default:
            return HTTPResponse(status: 404, text: "not found")
        }
    }

    private func group(_ groupID: Hash32, request: HTTPRequest, tail: [String], ip: String, now: Double) -> HTTPResponse {
        let bytes = Array(request.body)
        switch (request.method, tail[0]) {
        case ("POST", "messages"), ("POST", "attestations"), ("POST", "republishes"):
            if let wait = itemLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            guard !bytes.isEmpty, bytes.count <= configuration.maxItemBytes else { return HTTPResponse(status: 413, text: "item size") }
            guard hasRoom(for: bytes.count) else { return Self.full }
            let kind = NodeAPI.ItemKind(rawValue: tail[0])!
            switch accept(bytes, kind: kind, groupID: groupID) {
            case .success(let receipt):
                if kind != .attestation { wake(groupID: groupID, itemHash: receipt.body.itemHash, bytes: bytes) }
                return HTTPResponse(contentType: "application/octet-stream", body: Data(receipt.wire))
            case .failure(let why): return HTTPResponse(status: why == "not stored" ? 503 : 400, text: why)
            }
        case ("POST", "wake"):
            guard let registration = try? WakeRegistration.fromWire(bytes), registration.isValid else { return HTTPResponse(status: 400, text: "bad wake registration") }
            let body = registration.body
            guard body.groupID == groupID, body.nodePk == nodePk else { return HTTPResponse(status: 400, text: "wake not for this node") }
            guard mailbox.isMember(body.memberPk, of: groupID) else { return HTTPResponse(status: 403, text: "not a member") }
            let current = nowMs()
            guard body.handle.count <= WakeRegistration.maxHandleBytes, body.url.count <= 512,
                  registration.isRemoval || body.expires > current && body.expires <= current + WakeRegistration.maxLifetimeMs,
                  registration.isRemoval || body.url.hasPrefix("https://") || body.url.hasPrefix("http://") else { return HTTPResponse(status: 400, text: "bad wake terms") }
            wakes.register(registration)
            return HTTPResponse(status: 204, body: Data())
        case ("GET", "attestations"):
            guard let members = mailbox.genesis(groupID: groupID)?.genesis.members,
                  authorizedGet(request, allowed: { members.contains($0) }) else { return Self.unauthorizedGet }
            let records = mailbox.items(groupID: groupID).filter { $0.stored.kind == .attestation }.compactMap { item -> AttestationRecord? in
                guard let signed = try? SignedAttestation.fromWire(item.stored.bytes) else { return nil }
                return AttestationRecord(signed, committed: mailbox.commitment(of: item.hash))
            }
            return Self.json(records)
        case ("POST", "fetch"):
            if let wait = fetchLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            guard let fetchRequest = try? FetchRequest.fromWire(bytes) else { return HTTPResponse(status: 400, text: "bad fetch request") }
            guard fetchRequest.body.groupID == groupID else { return HTTPResponse(status: 400, text: "group mismatch") }
            let reply = serve(fetchRequest)
            return HTTPResponse(contentType: "application/octet-stream", body: Data(reply.wire))
        case ("POST", "genesis"):
            if let wait = genesisLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            guard bytes.count <= configuration.maxItemBytes else { return HTTPResponse(status: 413, text: "genesis size") }
            guard hasRoom(for: bytes.count) else { return Self.full }
            guard let record = try? GenesisRecord.fromWire(bytes), record.genesis.groupID == groupID else { return HTTPResponse(status: 400, text: "bad genesis") }
            guard record.genesis.homeNodes.contains(nodePk) else { return HTTPResponse(status: 403, text: "this node is not a home of the group") }
            if let existing = mailbox.genesis(groupID: groupID), existing.carrySigs.count >= record.carrySigs.count {
                mailbox.touchGenesis(groupID, at: nowMs())
                return HTTPResponse(status: 204, body: Data())
            }
            do { try mailbox.storeGenesis(record, at: nowMs()) } catch { return HTTPResponse(status: 503, text: "not stored") }
            return HTTPResponse(status: 204, body: Data())
        case ("GET", "genesis"):
            guard let record = mailbox.genesis(groupID: groupID) else { return HTTPResponse(status: 404, text: "no genesis held") }
            guard authorizedGet(request, allowed: { record.genesis.members.contains($0) }) else { return Self.unauthorizedGet }
            return HTTPResponse(contentType: "application/octet-stream", body: Data(record.wire))
        case ("POST", "acks"):
            if let wait = itemLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            guard bytes.count <= configuration.maxItemBytes, let ack = try? Ack.fromWire(bytes), ack.isValid else { return HTTPResponse(status: 400, text: "bad ack") }
            guard ack.body.groupID == groupID, ack.body.nodePk == nodePk else { return HTTPResponse(status: 400, text: "ack not for this node") }
            guard mailbox.genesis(groupID: groupID) != nil else { return HTTPResponse(status: 403, text: "not a group this node holds") }
            // An ack expires by its own time, which its sender chooses: only one about now.
            let current = nowMs()
            guard ack.body.time + Self.ackWindowMs >= current, ack.body.time <= current + Self.ackWindowMs else {
                return HTTPResponse(status: 400, text: "ack time too far from now")
            }
            guard hasRoom(for: bytes.count), mailbox.ackFits(groupID: groupID) else { return Self.full }
            mailbox.recordAck(ack)
            return HTTPResponse(status: 204, body: Data())
        case ("POST", "blobs"):
            if let wait = blobLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            guard tail.count == 2, let hash = Hash32(hex: tail[1]) else { return HTTPResponse(status: 400, text: "bad blob hash") }
            guard !bytes.isEmpty, bytes.count <= configuration.maxBlobBytes else { return HTTPResponse(status: 413, text: "blob size") }
            // A group this node is a home of (its genesis held here), within the node's budget.
            guard mailbox.genesis(groupID: groupID) != nil else { return HTTPResponse(status: 403, text: "not a group this node holds") }
            if let budget = configuration.maxBlobStoreBytes, mailbox.blobBytes + bytes.count > budget {
                return HTTPResponse(status: 507, text: "this node's blob storage is full")
            }
            guard hasRoom(for: bytes.count) else { return Self.full }
            let digest = Hashing.sha256(bytes)
            guard digest == hash else { return HTTPResponse(status: 400, text: "hash mismatch") }
            if let existing = mailbox.blob(groupID: groupID, hash: hash) { return HTTPResponse(contentType: "application/octet-stream", body: Data(existing.receipt.wire)) }
            let receipt = makeReceipt(groupID: groupID, itemHash: hash, digest: digest)
            do { try mailbox.storeBlob(bytes, receipt: receipt, groupID: groupID, hash: hash) } catch { return HTTPResponse(status: 503, text: "not stored") }
            return HTTPResponse(contentType: "application/octet-stream", body: Data(receipt.wire))
        case ("GET", "blobs"):
            guard tail.count == 2, let hash = Hash32(hex: tail[1]) else { return HTTPResponse(status: 400, text: "bad blob hash") }
            guard let blob = mailbox.blob(groupID: groupID, hash: hash) else { return HTTPResponse(status: 404, text: "no blob") }
            return HTTPResponse(contentType: "application/octet-stream", body: Data(blob.bytes))
        default:
            return HTTPResponse(status: 404, text: "not found")
        }
    }

    // MARK: §14 receipts

    /// Accepts an item it can parse whose group matches the path. The
    /// node does not check authorship (§5, members do); the receipt binds
    /// the node to the bytes and to the batch it names.
    public func accept(_ bytes: [UInt8], kind: NodeAPI.ItemKind, groupID: Hash32) -> Result<Receipt, String> {
        let itemHash: Hash32
        switch kind {
        case .message:
            guard let signed = try? SignedMessage.fromWire(bytes) else { return .failure("bad message") }
            guard signed.message.groupID == groupID else { return .failure("group mismatch") }
            itemHash = signed.hash
        case .attestation:
            guard let signed = try? SignedAttestation.fromWire(bytes) else { return .failure("bad attestation") }
            guard signed.attestation.groupID == groupID else { return .failure("group mismatch") }
            itemHash = signed.itemHash
        case .republish:
            guard let signed = try? SignedMessage.fromWire(bytes), signed.message.kind == Message.Kind.republish.rawValue else { return .failure("bad republish") }
            guard signed.message.groupID == groupID else { return .failure("group mismatch") }
            itemHash = signed.hash
        }
        let digest = Hashing.sha256(bytes)
        if let existing = mailbox.item(groupID: groupID, hash: itemHash), existing.digest == digest {
            return .success(existing.receipt)
        }
        let receipt = makeReceipt(groupID: groupID, itemHash: itemHash, digest: digest)
        do {
            try mailbox.store(.init(kind: kind, bytes: bytes, digest: digest, receipt: receipt), groupID: groupID, itemHash: itemHash)
        } catch {
            log?("store failed: \(error)")
            return .failure("not stored")
        }
        return .success(receipt)
    }

    /// Calls the relays registered for the group, except the author's own,
    /// with the item that landed (deviations: wakes). Best effort, off the
    /// request thread; a relay that will not answer costs nothing here.
    private func wake(groupID: Hash32, itemHash: Hash32, bytes: [UInt8]) {
        let current = nowMs()
        let registrations = wakes.registrations(groupID: groupID, at: current)
        guard !registrations.isEmpty else { return }
        let author = (try? SignedMessage.fromWire(bytes)).flatMap { signed in
            mailbox.genesis(groupID: groupID).flatMap { record in
                Int(signed.message.authorIdx) < record.genesis.members.count ? record.genesis.members[Int(signed.message.authorIdx)] : nil
            }
        }
        let now = clock()
        let body: [UInt8]? = bytes.count <= WakeCall.maxBodyBytes ? bytes : nil
        for registration in registrations where registration.body.memberPk != author {
            if wakeLimiter.retryAfter(registration.body.handle.hex, now: now) != nil { continue }
            let call = WakeCall.sign(handle: registration.body.handle, item: itemHash, body: body, time: current, with: key)
            guard let json = try? JSONEncoder().encode(call) else { continue }
            dispatch("POST", registration.body.url, json)
        }
    }

    func makeReceipt(groupID: Hash32, itemHash: Hash32, digest: Hash32) -> Receipt {
        let now = nowMs()
        let batch = openBatch()
        return Receipt.sign(.init(nodePk: nodePk, groupID: groupID, itemHash: itemHash, contentDigest: digest, batchSeq: batch.seq, batchPrev: batch.prev,
                                  received: now, deadline: now + configuration.deliveryWindowMs,
                                  retainUntil: now + configuration.retentionMs), with: key)
    }

    // MARK: §15 fetch

    /// Serves a signed request to a member of the group: every response is
    /// signed, `unauthorized` included.
    public func serve(_ request: FetchRequest) -> FetchReply {
        let now = nowMs()
        // §15: the response's time is at least the request's (the clocks of
        // the requester and the node may differ a little).
        let ahead = Parameters.Node.requestMaxAheadMs
        let answered = request.body.time <= now + ahead ? max(now, request.body.time) : now
        func reply(_ status: FetchStatus, _ served: [(Hash32, [UInt8])]) -> FetchReply {
            let body = FetchResponse.Body(nodePk: nodePk, requestHash: request.requestHash, status: status,
                                          served: served.map { ($0.0, Hashing.sha256($0.1)) }, time: answered)
            return FetchReply(response: FetchResponse.sign(body, with: key), items: served.map(\.1))
        }
        guard request.isValid else { return reply(.unauthorized, []) }
        let groupID = request.body.groupID
        guard groupID == NodeAPI.identityGroup || mailbox.isMember(request.body.requesterPk, of: groupID) else { return reply(.unauthorized, []) }
        if request.body.time > now + ahead || now > request.body.time + Parameters.Node.requestMaxAgeMs { return reply(.expired, []) }
        switch request.body.want {
        case .item(let hash):
            guard let stored = mailbox.item(groupID: groupID, hash: hash) else { return reply(.notFound, []) }
            return reply(.found, [(hash, stored.bytes)])
        case .blob(let hash):
            guard let blob = mailbox.blob(groupID: groupID, hash: hash) else { return reply(.notFound, []) }
            return reply(.found, [(hash, blob.bytes)])
        case .range(let sinceHead, let head):
            // Everything held for the group not under `sinceHead`; the
            // client walks its own DAG and discards what it already has.
            let items = mailbox.items(groupID: groupID)
            guard !items.isEmpty else { return reply(.notFound, []) }
            var exclude: Set<Hash32> = []
            if sinceHead != Hash32.zero {
                var dag = DAG(groupID: groupID, members: mailbox.genesis(groupID: groupID)?.genesis.members ?? [])
                var pending = items.compactMap { $0.stored.kind == .attestation ? nil : try? SignedMessage.fromWire($0.stored.bytes) }
                var progressed = true
                while progressed, !pending.isEmpty {
                    progressed = false
                    pending = pending.filter { if (try? dag.insert($0)) != nil { progressed = true; return false }; return true }
                }
                if dag.contains(sinceHead) { exclude = dag.ancestors(of: sinceHead) }
            }
            let selected = items.filter { !exclude.contains($0.hash) }.map { ($0.hash, $0.stored.bytes) }
            let complete = head == Hash32.zero || items.contains { $0.hash == head }
            return reply(complete ? .found : .partial, selected)
        }
    }

    // MARK: §19 signed GETs

    static let unauthorizedGet = HTTPResponse(status: 401, text: "signed GET required (X-Convo-Auth)")

    /// §19: a member-only GET carries `X-Convo-Auth`; the signature covers
    /// the method, the request target and a time within the window of this
    /// node's clock, and `allowed` says whether the signer may read the route.
    private func authorizedGet(_ request: HTTPRequest, allowed: (PublicKey) -> Bool) -> Bool {
        // The HTTP parser lowercases names; a request built in process may not.
        guard let header = request.headers.first(where: { $0.key.lowercased() == NodeAPI.authHeader.lowercased() })?.value,
              let (signer, time) = NodeAPI.verifyGetAuth(header, method: request.method, pathAndQuery: request.path) else { return false }
        let now = nowMs()
        guard time <= now + NodeAPI.authWindowMs, now <= time + NodeAPI.authWindowMs else { return false }
        return allowed(signer)
    }

    // MARK: §11 witnessing

    private func witness(_ request: HTTPRequest) -> HTTPResponse {
        guard let witnessRequest = try? WitnessRequest.fromWire(Array(request.body)) else { return HTTPResponse(status: 400, text: "bad witness request") }
        let node = witnessRequest.checkpoint.nodePk
        guard node != nodePk else { return HTTPResponse(status: 400, text: "a node does not witness itself") }
        let held = mailbox.witnessedEntries(of: node)
        switch mailbox.witness(witnessRequest, now: nowMs(), with: key) {
        case .cosign(let cosignature):
            return HTTPResponse(contentType: "application/octet-stream", body: Data(cosignature.borsh))
        case .resendFrom(let size):
            return HTTPResponse(status: 409, contentType: "application/octet-stream",
                                body: Data(NodeClient.witnessConflict(size: size, latest: mailbox.latestCheckpoint(of: node, own: nodePk))))
        case .conflict(let earlier):
            // Two checkpoints the node signed that can't both stand: F6.
            if let earlier {
                let entries = witnessRequest.fromSeq == UInt64(held.count) ? held + witnessRequest.entries : []
                if Checkpoint.equivocate(earlier, witnessRequest.checkpoint, entries: entries) {
                    let proof = FraudProof.f6(first: earlier, second: witnessRequest.checkpoint, entries: entries)
                    if accept(proof) { log?("F6: \(node.hex.prefix(8)) signed two histories") }
                }
            }
            return HTTPResponse(status: 409, contentType: "application/octet-stream",
                                body: Data(NodeClient.witnessConflict(size: UInt64(held.count), latest: mailbox.latestCheckpoint(of: node, own: nodePk))))
        case .rejected(let why):
            return HTTPResponse(status: 400, text: why)
        }
    }

    // MARK: §17 fraud proofs

    /// Keeps a proof that verifies and, the first time, passes it on to the
    /// nodes this node knows. False when it does not verify.
    @discardableResult
    public func accept(_ proof: FraudProof) -> Bool {
        guard case .success(let node) = proof.verify(witnessQuorum: mailbox.witnessQuorum) else { return false }
        guard mailbox.storeFraud(proof, against: node) else { return true }
        log?("fraud proof F\(proof.tag) against \(node.hex.prefix(8)) kept")
        lock.lock(); let targets = directory.healthy.map(\.url); lock.unlock()
        let body = Data(proof.wire)
        for url in targets { dispatch("POST", url + NodeAPI.fraud, body) }
        return true
    }

    /// A call nobody waits for: through `send`, else `fetch` in place.
    private func dispatch(_ method: String, _ url: String, _ body: Data?) {
        if let send { send(method, url, body); return }
        let (status, _) = fetch(method, url, body)
        if status < 200 || status >= 300 { log?("\(method) \(url) answered \(status)") }
    }

    // MARK: discovery (§24)

    private func advertiseReceived(_ request: HTTPRequest, ip: String, now: Double) -> HTTPResponse {
        if let wait = advertiseLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
        guard request.body.count <= 4096,
              let advertisement = try? JSONDecoder().decode(Advertisement.self, from: request.body) else {
            return HTTPResponse(status: 400, text: "expected {\"known_signaling_servers\": [urls]}")
        }
        var accepted = 0
        lock.lock()
        let own = configuration.publicURL.flatMap(ServerDirectory.normalize)
        for raw in advertisement.knownSignalingServers.prefix(20) {
            guard let url = ServerDirectory.normalize(raw), url != own else { continue }
            if directory.add(url, now: now) { accepted += 1 }
        }
        lock.unlock()
        if accepted > 0 { log?("advertised: \(accepted) new node(s) queued for health check") }
        return .json(["accepted": accepted], status: 202)
    }

    private func rendezvous(_ request: HTTPRequest, box: String, ip: String, now: Double) -> HTTPResponse {
        guard Self.isBoxID(box) else { return HTTPResponse(status: 400, text: "bad box id") }
        switch request.method {
        case "POST":
            if let wait = dropLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            guard !request.body.isEmpty, request.body.count <= Self.rendezvousMaxBytes else {
                return HTTPResponse(status: 413, text: "blob must be 1…\(Self.rendezvousMaxBytes) bytes")
            }
            let blob = String(decoding: request.body, as: UTF8.self)
            lock.lock()
            pruneBoxes(now: now)
            var queue = boxes[box] ?? []
            if queue.count >= Self.boxMaxBlobs { lock.unlock(); return HTTPResponse(status: 429, text: "box full") }
            if boxBytes + blob.utf8.count > Self.maxBoxBytes { lock.unlock(); return HTTPResponse(status: 429, text: "boxes full; retry later") }
            queue.append((blob, now))
            boxBytes += blob.utf8.count
            if boxes[box] == nil {
                boxOrder.append(box)
                while boxOrder.count > Self.maxBoxes, let oldest = boxOrder.first {
                    boxOrder.removeFirst()
                    boxBytes -= (boxes[oldest] ?? []).reduce(0) { $0 + $1.blob.utf8.count }
                    boxes[oldest] = nil
                }
            }
            boxes[box] = queue
            lock.unlock()
            return HTTPResponse(text: "ok")
        case "GET":
            if let wait = pollLimiter.retryAfter(ip, now: now) { return Self.tooMany(wait) }
            lock.lock()
            pruneBoxes(now: now)
            var queue = boxes[box] ?? []
            let first = queue.first
            if let first { queue.removeFirst(); boxes[box] = queue; boxBytes -= first.blob.utf8.count }
            lock.unlock()
            guard let first else { return HTTPResponse(status: 404, text: "empty") }
            return HTTPResponse(text: first.blob)
        default:
            return HTTPResponse(status: 405, text: "method")
        }
    }

    public func healthReport(now: Double) -> HealthReport {
        HealthReport(ok: true, id: configuration.id, kind: "node", version: Self.version,
                     site: configuration.site, turn: ice.offersTURN, now: now)
    }

    /// §24: the node's descriptor, signed now.
    public func descriptor() -> NodeDescriptor {
        NodeDescriptor.sign(operatorPk: configuration.operatorPk ?? nodePk, url: configuration.publicURL ?? "",
                            site: configuration.site ?? "", turn: ice.offersTURN, version: Self.version, time: nowMs(), with: key)
    }

    public func info(now: Double) -> NodeInfo {
        NodeInfo(descriptor: descriptor(), id: configuration.id, stun: ice.stunURLs,
                 deliveryWindowMs: configuration.deliveryWindowMs, retentionMs: configuration.retentionMs,
                 now: UInt64(max(0, now) * 1000), batchSeq: openBatch().seq)
    }

    public func serverList() -> ServerList {
        lock.lock(); defer { lock.unlock() }
        var entries: [ServerList.Entry] = []
        if let own = configuration.publicURL.flatMap(ServerDirectory.normalize) {
            entries.append(.init(url: own, id: configuration.id, site: configuration.site, turn: ice.offersTURN))
        }
        for server in directory.healthy {
            entries.append(.init(url: server.url, id: server.id, site: server.site, turn: server.turn))
        }
        return ServerList(servers: entries)
    }

    public var knownServers: ServerDirectory {
        lock.lock(); defer { lock.unlock() }
        return directory
    }

    // MARK: maintenance

    /// Once a minute or so: seed, health-check, discover, advertise,
    /// persist, expire.
    public func tick() {
        let now = clock()
        lock.lock()
        let own = configuration.publicURL.flatMap(ServerDirectory.normalize)
        for seed in pendingSeeds where ServerDirectory.normalize(seed) != own { directory.add(seed, now: now) }
        pendingSeeds = []
        lock.unlock()
        runHealthChecks(now: now)
        runDiscovery(now: now)
        advertise(now: now)
        persist()
        expireState()
    }

    /// Retention (§13): items past it, foreign bodies, wakes. The part of
    /// `tick` a host without blocking calls runs on its own.
    public func expireState() {
        let ms = nowMs()
        let expired = mailbox.expire(now: ms, foreignRetention: configuration.retentionMs)
        wakes.expire(now: ms)
        if expired > 0 { log?("expired \(expired) item(s) past retention") }
    }

    private func runHealthChecks(now: Double) {
        lock.lock(); let due = directory.due(now: now); lock.unlock()
        for server in due {
            let report = healthCheck(server.url)
            lock.lock()
            if let report {
                directory.recordHealthy(server.url, report: report, now: now)
            } else if directory.recordFailure(server.url, now: now) {
                log?("evicted \(server.url) after a week of failed checks")
            }
            lock.unlock()
        }
    }

    private func healthCheck(_ url: String) -> HealthReport? {
        let (status, data) = fetch("GET", url + NodeAPI.health, nil)
        guard (200..<300).contains(status), let data,
              let report = try? JSONDecoder().decode(HealthReport.self, from: data),
              report.ok, report.kind == "node" || report.kind == "signaling" else { return nil }
        return report
    }

    private func runDiscovery(now: Double) {
        lock.lock()
        guard directory.shouldDiscover(now: now) else { lock.unlock(); return }
        directory.markDiscovery(now: now)
        var walk = DiscoveryWalk(from: directory, seeds: configuration.seeds)
        let own = configuration.publicURL.flatMap(ServerDirectory.normalize)
        lock.unlock()
        var asked = 0
        while let url = walk.next() {
            if url == own { continue }
            lock.lock(); let satisfied = directory.satisfied; lock.unlock()
            if satisfied { break }
            asked += 1
            lock.lock()
            let unverified = directory.servers[url].map { !$0.isHealthy } ?? false
            lock.unlock()
            if unverified {
                let report = healthCheck(url)
                lock.lock()
                if let report { directory.recordHealthy(url, report: report, now: now) }
                else { directory.recordFailure(url, now: now) }
                lock.unlock()
            }
            let (status, data) = fetch("GET", url + "/servers", nil)
            guard (200..<300).contains(status), let data,
                  let list = try? JSONDecoder().decode(ServerList.self, from: data) else { continue }
            walk.absorb(list, from: url)
            lock.lock()
            for learned in walk.learned where learned != own {
                if directory.add(learned, now: now) {
                    lock.unlock()
                    let report = healthCheck(learned)
                    lock.lock()
                    if let report { directory.recordHealthy(learned, report: report, now: now) }
                    else { directory.recordFailure(learned, now: now) }
                }
            }
            lock.unlock()
        }
        if asked > 0 {
            lock.lock(); let healthy = directory.healthy.count; lock.unlock()
            log?("discovery: asked \(asked), \(healthy) healthy known")
        }
    }

    private func advertise(now: Double) {
        guard let own = configuration.publicURL.flatMap(ServerDirectory.normalize) else { return }
        lock.lock()
        guard now - lastAdvertised >= Self.advertiseInterval else { lock.unlock(); return }
        lastAdvertised = now
        let targets = directory.healthy.map(\.url)
        lock.unlock()
        guard let body = try? JSONEncoder().encode(Advertisement(knownSignalingServers: [own])) else { return }
        var reached = 0
        for url in targets where url != own {
            let (status, _) = fetch("POST", url + "/servers", body)
            if (200..<300).contains(status) { reached += 1 }
        }
        if !targets.isEmpty { log?("advertised to \(reached)/\(targets.count) nodes") }
    }

    /// The directory as last written, so an unchanged one isn't written again
    /// (each write is a billed operation on an object store).
    private var persistedDirectory: String?

    private func persist() {
        guard let dir = configuration.stateDirectory else { return }
        lock.lock()
        let text = directory.encoded()
        let changed = text != persistedDirectory
        if changed { persistedDirectory = text }
        lock.unlock()
        if changed { try? StateFiles.write(Data(text.utf8), to: dir + "/servers.json") }
    }

    private func pruneBoxes(now: Double) {
        for (box, queue) in boxes {
            let kept = queue.filter { now - $0.at < Self.blobLifetime }
            if kept.count != queue.count {
                boxBytes -= queue.filter { now - $0.at >= Self.blobLifetime }.reduce(0) { $0 + $1.blob.utf8.count }
            }
            if kept.isEmpty {
                boxes[box] = nil
                boxOrder.removeAll { $0 == box }
            } else if kept.count != queue.count {
                boxes[box] = kept
            }
        }
    }

    static func isBoxID(_ id: String) -> Bool {
        (8...64).contains(id.count) && id.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
    }

    static func split(_ raw: String) -> (path: String, query: [String: String]) {
        guard let q = raw.firstIndex(of: "?") else { return (raw, [:]) }
        var query: [String: String] = [:]
        for pair in raw[raw.index(after: q)...].split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            guard let key = parts.first else { continue }
            query[String(key)] = parts.count > 1 ? Self.percentDecoded(String(parts[1])) ?? String(parts[1]) : ""
        }
        return (String(raw[..<q]), query)
    }

    /// `%XX` escapes and `+` decoded, as a query value is; nil when an
    /// escape is malformed or the bytes aren't UTF-8.
    static func percentDecoded(_ text: String) -> String? {
        var out: [UInt8] = []
        var bytes = Array(text.utf8)[...]
        while let byte = bytes.popFirst() {
            switch byte {
            case UInt8(ascii: "%"):
                guard bytes.count >= 2, let value = UInt8(String(decoding: bytes.prefix(2), as: UTF8.self), radix: 16) else { return nil }
                out.append(value)
                bytes = bytes.dropFirst(2)
            case UInt8(ascii: "+"): out.append(UInt8(ascii: " "))
            default: out.append(byte)
            }
        }
        return String(validating: out, as: UTF8.self)
    }

    /// The client a rate limit counts: its IPv4 address, or its IPv6 /64
    /// (one subscriber's prefix, which it can fill with addresses at will).
    static func address(of peer: String) -> String {
        let host: String
        if peer.hasPrefix("["), let close = peer.firstIndex(of: "]") {
            host = String(peer[peer.index(after: peer.startIndex) ..< close])     // "[v6]:port"
        } else if peer.filter({ $0 == ":" }).count == 1, let colon = peer.lastIndex(of: ":") {
            host = String(peer[..<colon])                                          // "v4:port"
        } else {
            host = peer                                                            // a bare address
        }
        guard host.contains(":") else { return host }
        // An IPv4 client seen as IPv6 (::ffff:a.b.c.d, or its hex form): its IPv4 address.
        if host.lowercased().hasPrefix("::ffff:") {
            let tail = String(host.dropFirst(7))
            if tail.contains(".") { return tail }
            let parts = tail.split(separator: ":").compactMap { UInt16($0, radix: 16) }
            if parts.count == 2 { return "\(parts[0] >> 8).\(parts[0] & 0xff).\(parts[1] >> 8).\(parts[1] & 0xff)" }
        }
        return ipv6Prefix64(host) ?? host
    }

    /// The first four groups of an IPv6 address, "::" expanded: its /64.
    static func ipv6Prefix64(_ address: String) -> String? {
        let parts = address.components(separatedBy: "::")
        guard parts.count <= 2 else { return nil }
        let head = parts[0].isEmpty ? [] : parts[0].split(separator: ":").map(String.init)
        let tail = parts.count == 2 && !parts[1].isEmpty ? parts[1].split(separator: ":").map(String.init) : []
        guard head.count + tail.count <= 8 else { return nil }
        let groups = parts.count == 2 ? head + Array(repeating: "0", count: 8 - head.count - tail.count) + tail : head
        guard groups.count == 8, groups.allSatisfy({ $0.count <= 4 && UInt16($0, radix: 16) != nil }) else { return nil }
        return groups.prefix(4).map { String(UInt16($0, radix: 16)!, radix: 16) }.joined(separator: ":") + "::/64"
    }

    static func json<T: Encodable>(_ value: T) -> HTTPResponse {
        let data = (try? JSONEncoder().encode(value)) ?? Data("{}".utf8)
        return HTTPResponse(contentType: "application/json", body: data)
    }

    /// Whether `bytes` more fit the node's storage budget.
    func hasRoom(for bytes: Int) -> Bool {
        guard let budget = configuration.maxStoredBytes else { return true }
        return mailbox.storedBytes + bytes + Mailbox.objectOverhead <= budget
    }

    static let full = HTTPResponse(status: 507, text: "this node's storage is full")
    /// How far an ack's time may be from the node's clock.
    static let ackWindowMs: UInt64 = 10 * 60 * 1000

    static func tooMany(_ wait: Int) -> HTTPResponse {
        HTTPResponse(status: 429, text: "slow down; retry after \(wait)s")
    }
}

extension String: @retroactive Error {}

/// A JSON value of a few shapes, for ad-hoc responses.
struct AnyCodable: Encodable {
    let value: Any
    init(_ value: Any) { self.value = value }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case let v as UInt64: try c.encode(v)
        case let v as Int: try c.encode(v)
        case let v as String: try c.encode(v)
        case let v as [String]: try c.encode(v)
        case let v as Bool: try c.encode(v)
        default: try c.encodeNil()
        }
    }
}
