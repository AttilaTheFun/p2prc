import ConvoCore
import ConvoNet
import ConvoFoundation

/// §6–7 and §11 as steps a host drives: when to close a batch, closing it
/// into the log with a signed checkpoint, the request each witness gets, and
/// what its answer changes. No I/O and no waiting, so a host that sends the
/// requests itself (a Worker) and `Committer` (which awaits them) share it.
public final class LogKeeper: @unchecked Sendable {
    public let nodeKey: SigningKey
    public let mailbox: Mailbox
    public var commitIntervalMs = Parameters.Node.commitIntervalMs
    private let lock = NSLock()
    private var lastCommit: UInt64
    /// How much of this log each witness holds, by URL, so a request sends
    /// only the entries it lacks.
    private var witnessSizes: [String: UInt64] = [:]

    public var nodePk: PublicKey { nodeKey.publicKey }

    public init(nodeKey: SigningKey, mailbox: Mailbox) {
        self.nodeKey = nodeKey
        self.mailbox = mailbox
        lastCommit = mailbox.checkpoint?.checkpoint.time ?? 0
    }

    /// The open batch should close now (`BATCH_MAX`, or `COMMIT_INTERVAL`
    /// since the last with something in it).
    public func commitDue(now: UInt64) -> Bool {
        let open = mailbox.openCount
        lock.lock(); defer { lock.unlock() }
        return open >= Parameters.Node.batchMax || (open > 0 && now >= lastCommit + commitIntervalMs)
    }

    /// The newest checkpoint still needs cosignatures to be published.
    public var needsCosignatures: Bool {
        guard let current = mailbox.checkpoint else { return false }
        return !current.isPublished(quorum: mailbox.witnessQuorum)
    }

    /// Cosignatures enough for now: a quorum and one more.
    public var hasEnoughCosignatures: Bool {
        (mailbox.checkpoint?.witnesses.count ?? 0) >= mailbox.witnessQuorum + 1
    }

    /// Closes the open batch into the log at `now` (unix ms) and signs a
    /// checkpoint of the log. Nil when nothing is open or it can't be stored.
    public func close(now: UInt64) throws -> CommitmentBatch? {
        guard let batch = mailbox.closeBatch(with: nodeKey) else { return nil }
        // A log's times never go backwards (witnesses refuse it).
        let time = max(now, mailbox.checkpoint?.checkpoint.time ?? 0)
        try mailbox.recordPosted(batch, time: time)
        lock.lock(); lastCommit = time; lock.unlock()
        let entries = mailbox.logEntries
        guard let last = entries.last else { return nil }
        let checkpoint = Checkpoint.sign(log: MMR(leaves: entries.map(\.leaf)), entry: last, with: nodeKey)
        mailbox.recordCheckpoint(WitnessedCheckpoint(checkpoint: checkpoint))
        return batch
    }

    /// The request for the witness at `url`: the newest checkpoint and the
    /// entries the witness is thought to lack. Nil when there's nothing to ask.
    public func request(for url: String) -> WitnessRequest? {
        guard let current = mailbox.checkpoint else { return nil }
        let checkpoint = current.checkpoint
        let entries = mailbox.logEntries
        guard UInt64(entries.count) == checkpoint.size else { return nil }
        lock.lock(); let from = min(witnessSizes[url] ?? 0, checkpoint.size); lock.unlock()
        return WitnessRequest(checkpoint: checkpoint, fromSeq: from, entries: Array(entries[Int(from)...]))
    }

    /// What a witness answered to `request`. A cosignature joins the
    /// checkpoint; a 409 from a witness that is merely behind returns the
    /// request to resend from what it holds. Nil when there's nothing more to
    /// send it.
    public func apply(_ answer: NodeClient.WitnessAnswer, from url: String, to request: WitnessRequest) -> WitnessRequest? {
        let checkpoint = request.checkpoint
        switch answer {
        case .cosigned(let cosignature):
            guard cosignature.witnessPk != nodePk else { return nil }
            var witnessed = WitnessedCheckpoint(checkpoint: checkpoint)
            witnessed.add(cosignature)
            mailbox.recordCheckpoint(witnessed)
            lock.lock(); witnessSizes[url] = checkpoint.size; lock.unlock()
            return nil
        case .conflict(let size, let theirs):
            // Behind: resend from what it holds. Anything else is a witness
            // holding a history this node never signed.
            guard size < checkpoint.size, size != request.fromSeq, theirs.map({ $0.checkpoint.seq < checkpoint.seq }) ?? true else { return nil }
            let entries = mailbox.logEntries
            guard UInt64(entries.count) >= checkpoint.size else { return nil }
            return WitnessRequest(checkpoint: checkpoint, fromSeq: size, entries: Array(entries[Int(size)..<Int(checkpoint.size)]))
        }
    }

    /// §13: the other home nodes of every group with an item in the batch,
    /// which should get its body so proofs are available from any of them.
    public func pushTargets(_ batch: CommitmentBatch) -> Set<PublicKey> {
        var peers: Set<PublicKey> = []
        for leaf in batch.leaves {
            guard let (group, _) = mailbox.item(hash: leaf), let record = mailbox.genesis(groupID: group) else { continue }
            for n in record.genesis.homeNodes where n != nodePk { peers.insert(n) }
        }
        return peers
    }
}
