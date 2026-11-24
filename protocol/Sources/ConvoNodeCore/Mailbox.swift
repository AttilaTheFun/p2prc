import ConvoCore
import ConvoNet
import ConvoFoundation

/// The node's store (§13–14): items it has receipted with their receipts
/// and the batch each is promised to; blob bodies; KeyPackages by
/// identity; identity records; each hosted group's genesis; its log (the
/// batches it has closed, and its newest checkpoint with the cosignatures
/// gathered for it); batch bodies pushed by other nodes; its copies of the
/// logs it witnesses; fraud proofs; acks. A directory makes it durable:
/// every write lands before the receipt goes out.
public final class Mailbox: @unchecked Sendable {
    public struct Stored: Sendable {
        public let kind: NodeAPI.ItemKind
        public let bytes: [UInt8]
        public let digest: Hash32
        public let receipt: Receipt
        public var retainUntil: UInt64 { receipt.body.retainUntil }
        public var batchSeq: UInt64 { receipt.body.batchSeq }
    }

    /// A batch this node closed into its log: its body, when (unix ms).
    public struct Posted: Sendable {
        public let batch: CommitmentBatch
        public let time: UInt64
        public var entry: LogEntry { LogEntry(root: batch.root, time: time, count: batch.count) }
    }

    public enum Failure: Error, Equatable { case notDurable(String) }

    private let lock = NSLock()
    private var items: [Hash32: [Hash32: Stored]] = [:]
    private var order: [Hash32: [Hash32]] = [:]
    private var itemGroup: [Hash32: Hash32] = [:]
    private var blobs: [Hash32: [Hash32: (bytes: [UInt8], receipt: Receipt)]] = [:]
    private var keyPackages: [Hash32: [UInt8]] = [:]
    private var geneses: [Hash32: GenesisRecord] = [:]
    /// When each genesis was last posted (unix ms), for expiring the unused
    /// ones; counted from load for those read from disk.
    private var genesisPostedAt: [Hash32: UInt64] = [:]
    private var acks: [Ack] = []
    private var ackLeaves: Set<Hash32> = []
    /// Items of the batch being assembled (§7), in receipt order.
    private var openLeaves: [Hash32] = []
    private var openSeq: UInt64 = 0
    private var posted: [UInt64: Posted] = [:]
    private var itemBatch: [Hash32: UInt64] = [:]
    private var foreign: [Hash32: [UInt64: CommitmentBatch]] = [:]
    /// When each pushed body arrived (unix ms), for retention; nil until the
    /// first expiry pass stamps a body loaded without a record.
    private var foreignStoredAt: [Hash32: [UInt64: UInt64?]] = [:]
    /// The newest checkpoint of this node's log and its cosignatures.
    private var ownCheckpoint: WitnessedCheckpoint?
    /// The logs this node witnesses (§11).
    private var witnessed: [PublicKey: LogWitness] = [:]
    /// Fraud proofs held, by accused node and proof hash (§17).
    private var fraud: [PublicKey: [Hash32: [UInt8]]] = [:]
    private var identities: [PublicKey: IdentityRecord] = [:]
    public let directory: String?
    /// Cosignatures that publish a checkpoint of this node's log.
    public let witnessQuorum: Int

    public init(directory: String? = nil, witnessQuorum: Int = Parameters.Client.witnessQuorum) {
        self.directory = directory
        self.witnessQuorum = witnessQuorum
        if let directory { load(directory) }
    }

    // MARK: items

    /// Keeps the item; the write happens first so a receipt never names
    /// bytes that were lost with the process. The item joins the open batch.
    public func store(_ stored: Stored, groupID: Hash32, itemHash: Hash32) throws {
        try persist(groupID: groupID, itemHash: itemHash, stored: stored)
        lock.lock()
        if items[groupID]?[itemHash] == nil {
            order[groupID, default: []].append(itemHash)
            itemGroup[itemHash] = groupID
            if !openLeaves.contains(itemHash) { openLeaves.append(itemHash) }
            itemBatch[itemHash] = openSeq
        }
        items[groupID, default: [:]][itemHash] = stored
        lock.unlock()
        persistOpen()
    }

    public func item(groupID: Hash32, hash: Hash32) -> Stored? {
        lock.lock(); defer { lock.unlock() }
        return items[groupID]?[hash]
    }

    public func item(hash: Hash32) -> (groupID: Hash32, stored: Stored)? {
        lock.lock(); defer { lock.unlock() }
        guard let g = itemGroup[hash], let s = items[g]?[hash] else { return nil }
        return (g, s)
    }

    /// Every item of the group in the order the node accepted them.
    public func items(groupID: Hash32) -> [(hash: Hash32, stored: Stored)] {
        lock.lock(); defer { lock.unlock() }
        return (order[groupID] ?? []).compactMap { h in items[groupID]?[h].map { (h, $0) } }
    }

    public func groups() -> [Hash32] {
        lock.lock(); defer { lock.unlock() }
        return Array(items.keys)
    }

    public func storeBlob(_ bytes: [UInt8], receipt: Receipt, groupID: Hash32, hash: Hash32) throws {
        guard let directory else { lock.lock(); blobs[groupID, default: [:]][hash] = (bytes, receipt); lock.unlock(); return }
        let dir = "\(directory)/groups/\(groupID.hex)/blobs"
        do {
            try StateFiles.write(Data(receipt.wire + bytes), to: "\(dir)/\(hash.hex).bin")
        } catch { throw Failure.notDurable("\(error)") }
        lock.lock()
        blobs[groupID, default: [:]][hash] = (bytes, receipt)
        if itemBatch[hash] == nil { openLeaves.append(hash); itemBatch[hash] = openSeq; itemGroup[hash] = groupID }
        lock.unlock()
        persistOpen()
    }

    /// Whether `node` is a home of a group held here: one whose batch
    /// bodies this node takes (§13).
    public func isCoHome(_ node: PublicKey) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return geneses.values.contains { $0.genesis.homeNodes.contains(node) }
    }

    /// Every blob held, in bytes.
    public var blobBytes: Int {
        lock.lock(); defer { lock.unlock() }
        return blobs.values.reduce(0) { $0 + $1.values.reduce(0) { $0 + $1.bytes.count } }
    }

    public func blob(groupID: Hash32, hash: Hash32) -> (bytes: [UInt8], receipt: Receipt)? {
        lock.lock(); defer { lock.unlock() }
        return blobs[groupID]?[hash]
    }

    // MARK: key packages (identity-scoped items)

    public func storeKeyPackage(_ bytes: [UInt8], identity: Hash32) throws {
        let hash = Hashing.sha256(bytes)
        if let directory {
            let dir = "\(directory)/keypackages"
            do {
                try StateFiles.write(Data(bytes), to: "\(dir)/\(identity.hex).bin")
            } catch { throw Failure.notDurable("\(error)") }
        }
        lock.lock()
        keyPackages[identity] = bytes
        if itemBatch[hash] == nil { openLeaves.append(hash); itemBatch[hash] = openSeq; itemGroup[hash] = NodeAPI.identityGroup }
        lock.unlock()
        persistOpen()
    }

    public func keyPackage(identity: Hash32) -> [UInt8]? {
        lock.lock(); defer { lock.unlock() }
        return keyPackages[identity]
    }

    // MARK: identity records (§13.2)

    /// Keeps a valid record newer than the one held, and puts it in the open
    /// batch as an identity-scoped item. False when it is not newer.
    @discardableResult
    public func storeIdentity(_ record: IdentityRecord) throws -> Bool {
        lock.lock()
        let newer = identities[record.idPk].map { record.updated > $0.updated } ?? true
        lock.unlock()
        guard newer else { return false }
        if let directory {
            let dir = "\(directory)/identities"
            do {
                try StateFiles.write(Data(record.wire), to: "\(dir)/\(record.idPk.hex).bin")
            } catch { throw Failure.notDurable("\(error)") }
        }
        let hash = Hashing.sha256(record.wire)
        lock.lock()
        identities[record.idPk] = record
        if itemBatch[hash] == nil { openLeaves.append(hash); itemBatch[hash] = openSeq; itemGroup[hash] = NodeAPI.identityGroup }
        lock.unlock()
        persistOpen()
        return true
    }

    public func identity(_ idPk: PublicKey) -> IdentityRecord? {
        lock.lock(); defer { lock.unlock() }
        return identities[idPk]
    }

    // MARK: geneses (§13)

    public func storeGenesis(_ record: GenesisRecord, at time: UInt64 = 0) throws {
        if let directory {
            let dir = "\(directory)/genesis"
            do {
                try StateFiles.write(Data(record.wire), to: "\(dir)/\(record.genesis.groupID.hex).bin")
                if time != 0 { try StateFiles.write(Self.stamp(time), to: "\(dir)/\(record.genesis.groupID.hex).time") }
            } catch { throw Failure.notDurable("\(error)") }
        }
        lock.lock(); geneses[record.genesis.groupID] = record; genesisPostedAt[record.genesis.groupID] = time; lock.unlock()
    }

    /// A genesis posted again (members republish theirs while the group is
    /// in use): it stays. Written down at most once a day, so a node that
    /// restarts (a Worker's object, evicted when idle) still knows.
    public func touchGenesis(_ groupID: Hash32, at time: UInt64) {
        lock.lock()
        guard geneses[groupID] != nil else { lock.unlock(); return }
        let last = genesisPostedAt[groupID] ?? 0
        genesisPostedAt[groupID] = time
        lock.unlock()
        if let directory, last == 0 || time > last + 86_400_000 {
            try? StateFiles.write(Self.stamp(time), to: "\(directory)/genesis/\(groupID.hex).time")
        }
    }

    static func stamp(_ time: UInt64) -> Data { var w = BorshWriter(); w.u64(time); return Data(w.bytes) }

    /// What each object held costs beyond its bytes: its file's path and
    /// entry in the host's file table and the mailbox's own (a Worker
    /// holds both in memory), so many small records count as what they use.
    public static let objectOverhead = 512

    /// Everything held for others, in bytes: what a node's storage budget
    /// counts (items, blobs, key packages, identities, geneses, acks, other
    /// nodes' batch bodies, fraud proofs), each object with its overhead.
    public var storedBytes: Int {
        lock.lock(); defer { lock.unlock() }
        var total = 0
        var objects = keyPackages.count + identities.count + geneses.count + acks.count
        for byHash in items.values { objects += byHash.count }
        for byHash in blobs.values { objects += byHash.count }
        for bySeq in foreign.values { objects += bySeq.count }
        for byHash in fraud.values { objects += byHash.count }
        total += objects * Self.objectOverhead
        for byHash in items.values { for stored in byHash.values { total += stored.bytes.count + Receipt.wireCount } }
        for byHash in blobs.values { for blob in byHash.values { total += blob.bytes.count + Receipt.wireCount } }
        for bytes in keyPackages.values { total += bytes.count }
        for record in identities.values { total += record.wire.count }
        for record in geneses.values { total += record.wire.count }
        for bySeq in foreign.values { for batch in bySeq.values { total += batch.wire.count } }
        for byHash in fraud.values { for proof in byHash.values { total += proof.count } }
        for ack in acks { total += ack.wire.count }
        return total
    }

    public func genesis(groupID: Hash32) -> GenesisRecord? {
        lock.lock(); defer { lock.unlock() }
        return geneses[groupID]
    }

    /// Whether `gk` is a member of the group (§15 authorization).
    public func isMember(_ gk: PublicKey, of groupID: Hash32) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return geneses[groupID]?.genesis.members.contains(gk) ?? false
    }

    // MARK: batches (§6–7)

    /// The batch receipts name now, and the root of the one before it.
    public var openBatch: (seq: UInt64, prev: Hash32) {
        lock.lock(); defer { lock.unlock() }
        return (openSeq, openSeq == 0 ? Hash32.zero : (posted[openSeq - 1]?.batch.root ?? Hash32.zero))
    }

    public var openCount: Int { lock.lock(); defer { lock.unlock() }; return openLeaves.count }

    /// Closes the open batch: its leaves go out as a signed body, the next
    /// receipt names `seq + 1`. Nil when nothing was receipted.
    public func closeBatch(with key: SigningKey) -> CommitmentBatch? {
        lock.lock()
        guard !openLeaves.isEmpty else { lock.unlock(); return nil }
        let seq = openSeq
        let prev = seq == 0 ? Hash32.zero : (posted[seq - 1]?.batch.root ?? Hash32.zero)
        let batch = CommitmentBatch.sign(nodePk: key.publicKey, seq: seq, prevRoot: prev, leaves: openLeaves, with: key)
        lock.unlock()
        return batch
    }

    /// The closed batch joins the log at `time` (unix ms), and the next
    /// batch opens.
    public func recordPosted(_ batch: CommitmentBatch, time: UInt64) throws {
        if let directory {
            let dir = "\(directory)/batches"
            do {
                var w = BorshWriter(); w.u64(time); w.vec(batch.wire)
                try StateFiles.write(w.bytes, to: "\(dir)/\(batch.seq).bin")
            } catch { throw Failure.notDurable("\(error)") }
        }
        lock.lock()
        posted[batch.seq] = Posted(batch: batch, time: time)
        if batch.seq == openSeq {
            openLeaves.removeAll { batch.leaves.contains($0) }
            openSeq = batch.seq + 1
            for leaf in openLeaves { itemBatch[leaf] = openSeq }
        }
        lock.unlock()
        persistOpen()
    }

    /// Test hook (D.5): drops a receipted item from the open batch, so the
    /// batch is posted without it and F4 applies.
    public func omitFromOpenBatch(_ item: Hash32) {
        lock.lock(); openLeaves.removeAll { $0 == item }; lock.unlock()
        persistOpen()
    }

    public func postedBatch(seq: UInt64) -> Posted? { lock.lock(); defer { lock.unlock() }; return posted[seq] }
    public var postedSeqs: [UInt64] { lock.lock(); defer { lock.unlock() }; return posted.keys.sorted() }

    /// The log's entries, oldest first.
    public var logEntries: [LogEntry] {
        lock.lock(); defer { lock.unlock() }
        return posted.keys.sorted().map { posted[$0]!.entry }
    }

    /// The node's log accumulator, rebuilt from every batch it closed.
    public var mmr: MMR { MMR(leaves: logEntries.map(\.leaf)) }

    /// The batch an item was promised to.
    public func batchSeq(of item: Hash32) -> UInt64? { lock.lock(); defer { lock.unlock() }; return itemBatch[item] }

    /// The `CommitmentRef` for an item in a published batch of this node's log (§6).
    public func commitment(of item: Hash32) -> CommitmentRef? {
        lock.lock()
        guard let seq = itemBatch[item], let p = posted[seq], let checkpoint = ownCheckpoint,
              checkpoint.checkpoint.seq >= seq, checkpoint.isPublished(quorum: witnessQuorum) else { lock.unlock(); return nil }
        lock.unlock()
        return p.batch.reference(item: item, time: p.time, mmr: mmr, checkpoint: checkpoint)
    }

    // MARK: this node's checkpoints (§6, §11)

    /// The newest checkpoint of this node's log, with its cosignatures.
    public var checkpoint: WitnessedCheckpoint? { lock.lock(); defer { lock.unlock() }; return ownCheckpoint }

    /// The newest published checkpoint covers batch `seq`.
    public func isPublished(seq: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let c = ownCheckpoint else { return false }
        return c.checkpoint.seq >= seq && c.isPublished(quorum: witnessQuorum)
    }

    /// Keeps a newer checkpoint of this node's log, or merges cosignatures
    /// into the one held. Persisted before it is served.
    public func recordCheckpoint(_ witnessed: WitnessedCheckpoint) {
        lock.lock()
        if let current = ownCheckpoint, current.checkpoint == witnessed.checkpoint {
            var merged = current
            for c in witnessed.cosignatures { merged.add(c) }
            ownCheckpoint = merged
        } else if ownCheckpoint.map({ witnessed.checkpoint.seq > $0.checkpoint.seq }) ?? true {
            ownCheckpoint = witnessed
        }
        let bytes = ownCheckpoint?.wire
        lock.unlock()
        if let directory, let bytes {
            try? StateFiles.write(Data(bytes), to: "\(directory)/batches/checkpoint.bin")
        }
    }

    // MARK: witnessing other logs (§11)

    /// Answers a witness request against this node's copy of that log.
    public func witness(_ request: WitnessRequest, now: UInt64, with key: SigningKey) -> LogWitness.Answer {
        let node = request.checkpoint.nodePk
        lock.lock()
        var log = witnessed[node] ?? LogWitness(nodePk: node)
        let answer = log.witness(request, now: now, with: key)
        if case .cosign = answer { witnessed[node] = log }
        lock.unlock()
        if case .cosign = answer { persistWitness(log) }
        return answer
    }

    /// The newest witnessed checkpoint held for a log: this node's own, or
    /// one it witnessed or was shown.
    public func latestCheckpoint(of node: PublicKey, own: PublicKey) -> WitnessedCheckpoint? {
        lock.lock(); defer { lock.unlock() }
        return node == own ? ownCheckpoint : witnessed[node]?.latest
    }

    /// Records a checkpoint of another node's log seen through gossip.
    public func observe(_ checkpoint: WitnessedCheckpoint) {
        let node = checkpoint.checkpoint.nodePk
        lock.lock()
        var log = witnessed[node] ?? LogWitness(nodePk: node)
        log.observe(checkpoint)
        witnessed[node] = log
        lock.unlock()
        persistWitness(log)
    }

    /// The entries this node holds of a log it witnesses.
    public func witnessedEntries(of node: PublicKey) -> [LogEntry] {
        lock.lock(); defer { lock.unlock() }
        return witnessed[node]?.entries ?? []
    }

    // MARK: fraud proofs (§17)

    /// Keeps a proof that verifies; false when it was already held.
    @discardableResult
    public func storeFraud(_ proof: FraudProof, against node: PublicKey) -> Bool {
        let wire = proof.wire
        let hash = Hashing.sha256(wire)
        lock.lock()
        let isNew = fraud[node]?[hash] == nil
        fraud[node, default: [:]][hash] = wire
        lock.unlock()
        if isNew, let directory {
            let dir = "\(directory)/fraud/\(node.hex)"
            try? StateFiles.write(Data(wire), to: "\(dir)/\(hash.hex).bin")
        }
        return isNew
    }

    public func fraudProofs(against node: PublicKey) -> [[UInt8]] {
        lock.lock(); defer { lock.unlock() }
        return (fraud[node] ?? [:]).sorted { $0.key < $1.key }.map(\.value)
    }

    /// The nodes this node holds a fraud proof against.
    public var provenFaulty: Set<PublicKey> { lock.lock(); defer { lock.unlock() }; return Set(fraud.keys) }

    // MARK: batch bodies from other nodes (§13)

    /// Keeps a body another node pushed (§13), stamped with when it arrived
    /// (unix ms) so retention can let it go with the items it proves.
    public func storeForeign(_ batch: CommitmentBatch, at time: UInt64 = 0) throws {
        guard batch.isValid else { throw Failure.notDurable("bad batch signature") }
        if let directory {
            let dir = "\(directory)/foreign/\(batch.nodePk.hex)"
            do {
                try StateFiles.write(Data(batch.wire), to: "\(dir)/\(batch.seq).bin")
                var w = BorshWriter(); w.u64(time)
                try StateFiles.write(Data(w.bytes), to: "\(dir)/\(batch.seq).time")
            } catch { throw Failure.notDurable("\(error)") }
        }
        lock.lock()
        foreign[batch.nodePk, default: [:]][batch.seq] = batch
        foreignStoredAt[batch.nodePk, default: [:]][batch.seq] = time
        lock.unlock()
    }

    public func batch(node: PublicKey, seq: UInt64) -> CommitmentBatch? {
        lock.lock(); defer { lock.unlock() }
        return foreign[node]?[seq]
    }

    // MARK: acks (§16)

    @discardableResult
    public func recordAck(_ ack: Ack) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let leaf = ack.leaf
        guard !ackLeaves.contains(leaf), hasRoomForAck(in: ack.body.groupID) else { return false }
        ackLeaves.insert(leaf)
        acks.append(ack)
        if let directory {
            let dir = "\(directory)/acks"
            try? StateFiles.write(Data(ack.wire), to: "\(dir)/\(leaf.hex).bin")
        }
        return true
    }

    public var pendingAcks: [Ack] { lock.lock(); defer { lock.unlock() }; return acks }

    /// Acks held at most: each a few hundred bytes, kept until retention;
    /// and in one group, so no one group's fill the rest.
    public static let maxAcks = 20_000
    public static let maxAcksPerGroup = 1_000

    /// Whether another ack fits, in all and in its group. (Under the lock.)
    private func hasRoomForAck(in groupID: Hash32) -> Bool {
        acks.count < Self.maxAcks && acks.lazy.filter { $0.body.groupID == groupID }.count < Self.maxAcksPerGroup
    }

    /// Whether another ack for `groupID` would be kept.
    public func ackFits(groupID: Hash32) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return hasRoomForAck(in: groupID)
    }

    // MARK: retention (§13)

    /// Drops items whose retention horizon (unix ms) has passed and whose
    /// batch is published. Blobs go with the group's last item. With
    /// `foreignRetention` (ms), bodies pushed by other nodes go once they
    /// are that old (a body is only ever needed while the items it proves
    /// are held somewhere).
    @discardableResult
    public func expire(now: UInt64, foreignRetention: UInt64? = nil) -> Int {
        lock.lock()
        let publishedThrough: UInt64? = ownCheckpoint.flatMap { $0.isPublished(quorum: witnessQuorum) ? $0.checkpoint.seq : nil }
        var dropped: [(Hash32, Hash32)] = []
        if let publishedThrough {
            for (group, byHash) in items {
                for (hash, stored) in byHash where stored.retainUntil < now && stored.batchSeq <= publishedThrough && posted[stored.batchSeq] != nil {
                    dropped.append((group, hash))
                }
            }
        }
        // A blob goes when its own horizon has passed and its batch is
        // published, as an item does, or with its group's last item.
        var droppedBlobs: [(Hash32, Hash32)] = []
        if let publishedThrough {
            for (group, byHash) in blobs {
                for (hash, blob) in byHash where blob.receipt.body.retainUntil < now && blob.receipt.body.batchSeq <= publishedThrough {
                    droppedBlobs.append((group, hash))
                }
            }
        }
        for (group, hash) in dropped {
            items[group]?[hash] = nil
            order[group]?.removeAll { $0 == hash }
            itemGroup[hash] = nil
            if items[group]?.isEmpty == true {
                items[group] = nil; order[group] = nil
                for hash in (blobs[group] ?? [:]).keys where !droppedBlobs.contains(where: { $0 == (group, hash) }) { droppedBlobs.append((group, hash)) }
            }
        }
        for (group, hash) in droppedBlobs {
            blobs[group]?[hash] = nil
            if blobs[group]?.isEmpty == true { blobs[group] = nil }
        }
        // A genesis no one has used (no item, no blob) or posted again for
        // `foreignRetention`: anyone may post one naming this node, so one
        // that's left alone goes (a group in use is republished by its members).
        var droppedAcks: [Hash32] = []
        if let foreignRetention {
            for ack in acks where ack.body.time + foreignRetention < now { droppedAcks.append(ack.leaf) }
            if !droppedAcks.isEmpty {
                let gone = Set(droppedAcks)
                acks.removeAll { gone.contains($0.leaf) }
                ackLeaves.subtract(gone)
            }
        }
        var droppedGeneses: [Hash32] = []
        var restamped: [Hash32] = []
        if let foreignRetention {
            for group in geneses.keys where items[group] == nil && blobs[group] == nil {
                guard let postedAt = genesisPostedAt[group], postedAt != 0 else { genesisPostedAt[group] = now; restamped.append(group); continue }
                if postedAt + foreignRetention < now { droppedGeneses.append(group) }
            }
            for group in droppedGeneses { geneses[group] = nil; genesisPostedAt[group] = nil }
        }
        var droppedForeign: [(Hash32, UInt64)] = []
        if let foreignRetention {
            for (node, bySeq) in foreign {
                for seq in bySeq.keys {
                    guard let storedAt = foreignStoredAt[node]?[seq] ?? nil else {
                        // Loaded without a record: counts from now.
                        foreignStoredAt[node, default: [:]][seq] = now
                        continue
                    }
                    if storedAt + foreignRetention < now { droppedForeign.append((node, seq)) }
                }
            }
            for (node, seq) in droppedForeign {
                foreign[node]?[seq] = nil
                foreignStoredAt[node]?[seq] = nil
                if foreign[node]?.isEmpty == true { foreign[node] = nil; foreignStoredAt[node] = nil }
            }
        }
        lock.unlock()
        if let directory {
            let fm = FileManager.default
            for (group, hash) in dropped {
                try? fm.removeItem(atPath: "\(directory)/groups/\(group.hex)/items/\(hash.hex).bin")
            }
            for (group, hash) in droppedBlobs {
                try? fm.removeItem(atPath: "\(directory)/groups/\(group.hex)/blobs/\(hash.hex).bin")
            }
            for leaf in droppedAcks { try? fm.removeItem(atPath: "\(directory)/acks/\(leaf.hex).bin") }
            for group in droppedGeneses {
                try? fm.removeItem(atPath: "\(directory)/genesis/\(group.hex).bin")
                try? fm.removeItem(atPath: "\(directory)/genesis/\(group.hex).time")
            }
            // One read with no time (from before times were kept): counted from now, and written so a restart doesn't reset it.
            for group in restamped { try? StateFiles.write(Self.stamp(now), to: "\(directory)/genesis/\(group.hex).time") }
            for (node, seq) in droppedForeign {
                try? fm.removeItem(atPath: "\(directory)/foreign/\(node.hex)/\(seq).bin")
                try? fm.removeItem(atPath: "\(directory)/foreign/\(node.hex)/\(seq).time")
            }
        }
        return dropped.count + droppedBlobs.count + droppedGeneses.count + droppedAcks.count + droppedForeign.count
    }

    /// Bodies held for a node.
    public func foreignSeqs(node: PublicKey) -> [UInt64] {
        lock.lock(); defer { lock.unlock() }
        return Array((foreign[node] ?? [:]).keys).sorted()
    }

    // MARK: durability

    private func persist(groupID: Hash32, itemHash: Hash32, stored: Stored) throws {
        guard let directory else { return }
        let dir = "\(directory)/groups/\(groupID.hex)/items"
        var w = BorshWriter()
        w.string(stored.kind.rawValue)
        w.vec(stored.receipt.wire)
        w.vec(stored.bytes)
        do {
            try StateFiles.write(Data(w.bytes), to: "\(dir)/\(itemHash.hex).bin")
        } catch {
            throw Failure.notDurable("\(error)")
        }
    }

    private func persistOpen() {
        guard let directory else { return }
        lock.lock()
        var w = BorshWriter(); w.u64(openSeq); w.vec(openLeaves) { w, l in w.fixed(l) }
        let bytes = w.bytes
        lock.unlock()
        try? StateFiles.write(Data(bytes), to: "\(directory)/batches/open.bin")
    }

    private func persistWitness(_ log: LogWitness) {
        guard let directory else { return }
        let dir = "\(directory)/witness"
        var w = BorshWriter()
        w.vec(log.entries) { w, e in e.borshEncode(into: &w) }
        w.option(log.latest) { w, c in c.borshEncode(into: &w) }
        try? StateFiles.write(Data(w.bytes), to: "\(dir)/\(log.nodePk.hex).bin")
    }

    private func load(_ directory: String) {
        let fm = FileManager.default
        for file in (try? fm.contentsOfDirectory(atPath: "\(directory)/batches")) ?? [] where file.hasSuffix(".bin") && file != "open.bin" && file != "checkpoint.bin" {
            guard let data = fm.contents(atPath: "\(directory)/batches/\(file)") else { continue }
            var r = BorshReader(Array(data))
            guard let time = try? r.u64(), let wire = try? r.vec(), let batch = try? CommitmentBatch.fromWire(wire) else { continue }
            posted[batch.seq] = Posted(batch: batch, time: time)
            for leaf in batch.leaves { itemBatch[leaf] = batch.seq }
        }
        if let data = fm.contents(atPath: "\(directory)/batches/open.bin") {
            var r = BorshReader(Array(data))
            if let seq = try? r.u64(), let leaves = try? r.vec({ try $0.hash32() }) {
                openSeq = seq; openLeaves = leaves
                for leaf in leaves { itemBatch[leaf] = seq }
            }
        }
        if openSeq == 0, let last = posted.keys.max() { openSeq = last + 1 }
        if let data = fm.contents(atPath: "\(directory)/batches/checkpoint.bin") { ownCheckpoint = try? WitnessedCheckpoint.fromWire(Array(data)) }
        let groupsDir = "\(directory)/groups"
        for groupHex in (try? fm.contentsOfDirectory(atPath: groupsDir)) ?? [] {
            guard let groupID = Hash32(hex: groupHex) else { continue }
            let itemsDir = "\(groupsDir)/\(groupHex)/items"
            for file in ((try? fm.contentsOfDirectory(atPath: itemsDir)) ?? []).sorted() {
                guard let data = fm.contents(atPath: "\(itemsDir)/\(file)") else { continue }
                var r = BorshReader(Array(data))
                guard let kindRaw = try? r.string(), let kind = NodeAPI.ItemKind(rawValue: kindRaw),
                      let receiptWire = try? r.vec(), let receipt = try? Receipt.fromWire(receiptWire),
                      let bytes = try? r.vec() else { continue }
                let hash = receipt.body.itemHash
                if items[groupID]?[hash] == nil { order[groupID, default: []].append(hash) }
                items[groupID, default: [:]][hash] = Stored(kind: kind, bytes: bytes, digest: Hashing.sha256(bytes), receipt: receipt)
                itemGroup[hash] = groupID
                if itemBatch[hash] == nil { itemBatch[hash] = receipt.body.batchSeq; if posted[receipt.body.batchSeq] == nil, !openLeaves.contains(hash) { openLeaves.append(hash) } }
            }
            let blobsDir = "\(groupsDir)/\(groupHex)/blobs"
            for file in (try? fm.contentsOfDirectory(atPath: blobsDir)) ?? [] {
                guard let hash = Hash32(hex: String(file.dropLast(4))), let data = fm.contents(atPath: "\(blobsDir)/\(file)"),
                      data.count > Receipt.wireCount, let receipt = try? Receipt.fromWire(Array(data.prefix(Receipt.wireCount))) else { continue }
                blobs[groupID, default: [:]][hash] = (Array(data.dropFirst(Receipt.wireCount)), receipt)
                itemGroup[hash] = groupID
            }
        }
        for file in ((try? fm.contentsOfDirectory(atPath: "\(directory)/acks")) ?? []).sorted() {
            guard let data = fm.contents(atPath: "\(directory)/acks/\(file)"), let ack = try? Ack.fromWire(Array(data)) else { continue }
            if ackLeaves.insert(ack.leaf).inserted { acks.append(ack) }
        }
        let kpDir = "\(directory)/keypackages"
        for file in (try? fm.contentsOfDirectory(atPath: kpDir)) ?? [] {
            guard let identity = Hash32(hex: String(file.dropLast(4))), let data = fm.contents(atPath: "\(kpDir)/\(file)") else { continue }
            keyPackages[identity] = Array(data)
        }
        for file in (try? fm.contentsOfDirectory(atPath: "\(directory)/genesis")) ?? [] where file.hasSuffix(".bin") {
            guard let data = fm.contents(atPath: "\(directory)/genesis/\(file)"), let record = try? GenesisRecord.fromWire(Array(data)) else { continue }
            geneses[record.genesis.groupID] = record
            if let stamp = fm.contents(atPath: "\(directory)/genesis/\(record.genesis.groupID.hex).time") {
                var r = BorshReader(Array(stamp)); genesisPostedAt[record.genesis.groupID] = (try? r.u64()) ?? 0
            }
        }
        for nodeHex in (try? fm.contentsOfDirectory(atPath: "\(directory)/foreign")) ?? [] {
            for file in (try? fm.contentsOfDirectory(atPath: "\(directory)/foreign/\(nodeHex)")) ?? [] {
                guard file.hasSuffix(".bin"), let data = fm.contents(atPath: "\(directory)/foreign/\(nodeHex)/\(file)"),
                      let batch = try? CommitmentBatch.fromWire(Array(data)) else { continue }
                foreign[batch.nodePk, default: [:]][batch.seq] = batch
                var storedAt: UInt64? = nil
                if let stamp = fm.contents(atPath: "\(directory)/foreign/\(nodeHex)/\(batch.seq).time") {
                    var r = BorshReader(Array(stamp)); storedAt = try? r.u64()
                }
                foreignStoredAt[batch.nodePk, default: [:]][batch.seq] = storedAt
            }
        }
        for file in (try? fm.contentsOfDirectory(atPath: "\(directory)/identities")) ?? [] {
            guard let data = fm.contents(atPath: "\(directory)/identities/\(file)"), let record = try? IdentityRecord.fromWire(Array(data)), record.isValid else { continue }
            identities[record.idPk] = record
        }
        for file in (try? fm.contentsOfDirectory(atPath: "\(directory)/witness")) ?? [] {
            guard let node = Hash32(hex: String(file.dropLast(4))), let data = fm.contents(atPath: "\(directory)/witness/\(file)") else { continue }
            var r = BorshReader(Array(data))
            guard let entries = try? r.vec({ try LogEntry(borshFrom: &$0) }),
                  let latest = try? r.option({ try WitnessedCheckpoint(borshFrom: &$0) }) else { continue }
            witnessed[node] = LogWitness(nodePk: node, entries: entries, latest: latest)
        }
        for nodeHex in (try? fm.contentsOfDirectory(atPath: "\(directory)/fraud")) ?? [] {
            guard let node = Hash32(hex: nodeHex) else { continue }
            for file in (try? fm.contentsOfDirectory(atPath: "\(directory)/fraud/\(nodeHex)")) ?? [] {
                guard let hash = Hash32(hex: String(file.dropLast(4))), let data = fm.contents(atPath: "\(directory)/fraud/\(nodeHex)/\(file)") else { continue }
                fraud[node, default: [:]][hash] = Array(data)
            }
        }
    }
}
