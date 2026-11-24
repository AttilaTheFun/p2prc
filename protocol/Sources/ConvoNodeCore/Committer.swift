import ConvoCore
import ConvoNet
import ConvoFoundation

/// §6–7 and §11: closes the node's open batch every `COMMIT_INTERVAL` (or at
/// `BATCH_MAX`), appends it to the node's log, signs a checkpoint of the
/// log, gathers cosignatures from witnesses until the checkpoint is
/// published, and pushes the body to the other home nodes of the groups it
/// covers. The steps are `LogKeeper`'s; this actor sends the requests and
/// awaits them.
public actor Committer {
    public let keeper: LogKeeper
    public var log: (@Sendable (String) -> Void)?
    /// How a batch body reaches a peer node by key (nil: unknown peer).
    public var peerClient: (@Sendable (PublicKey) async -> NodeClient?)?
    /// The witnesses to ask, best first, by URL (§11: healthy nodes,
    /// preferring other operators and sites).
    public var witnesses: (@Sendable () async -> [(url: String, client: NodeClient)])?
    /// Unix ms.
    public let clock: @Sendable () -> UInt64
    /// Whether this instance may write the node's state (`StateLease`).
    public var mayWrite: @Sendable () -> Bool = { true }
    private var committing = false

    public nonisolated var nodePk: PublicKey { keeper.nodePk }

    public init(nodeKey: SigningKey, mailbox: Mailbox, clock: @escaping @Sendable () -> UInt64 = { Parameters.nowMs() }) {
        self.keeper = LogKeeper(nodeKey: nodeKey, mailbox: mailbox)
        self.clock = clock
    }

    public func setLog(_ log: @escaping @Sendable (String) -> Void) { self.log = log }
    public func setPeerClient(_ resolve: @escaping @Sendable (PublicKey) async -> NodeClient?) { peerClient = resolve }
    public func setWitnesses(_ list: @escaping @Sendable () async -> [(url: String, client: NodeClient)]) { witnesses = list }
    public func setCommitInterval(_ ms: UInt64) { keeper.commitIntervalMs = ms }
    public func setMayWrite(_ check: @escaping @Sendable () -> Bool) { mayWrite = check }

    /// Every poll: a commit when due, else more cosignatures for a
    /// checkpoint that isn't published yet.
    public func poll() async {
        if keeper.commitDue(now: clock()) {
            await commit()
        } else if keeper.needsCosignatures {
            await gatherCosignatures()
        }
    }

    /// Closes the open batch into the log and checkpoints it (§7). A
    /// checkpoint that can't be published yet is retried on later polls.
    @discardableResult
    public func commit() async -> CommitmentBatch? {
        guard !committing, mayWrite() else { return nil }
        committing = true
        defer { committing = false }
        let batch: CommitmentBatch
        do {
            guard let closed = try keeper.close(now: clock()) else { return nil }
            batch = closed
        } catch {
            log?("batch not stored: \(error)")
            return nil
        }
        log?("closed batch \(batch.seq): \(batch.count) item(s)")
        await gatherCosignatures()
        await push(batch)
        return batch
    }

    /// §11: asks witnesses to cosign the newest checkpoint until it has a
    /// quorum and one more, sending each the entries it lacks.
    public func gatherCosignatures() async {
        guard mayWrite(), let witnesses else { return }
        for (url, client) in await witnesses() {
            if keeper.hasEnoughCosignatures { break }
            guard var request = keeper.request(for: url) else { return }
            for _ in 0..<2 {
                let answer: NodeClient.WitnessAnswer
                do { answer = try await client.witness(request) } catch {
                    log?("witness \(url) failed: \(error)")
                    break
                }
                guard let retry = keeper.apply(answer, from: url, to: request) else { break }
                request = retry
            }
        }
        let mailbox = keeper.mailbox
        let have = mailbox.checkpoint?.witnesses.count ?? 0
        if have < mailbox.witnessQuorum, let seq = mailbox.checkpoint?.checkpoint.seq {
            log?("checkpoint \(seq): \(have) of \(mailbox.witnessQuorum) cosignatures")
        }
    }

    /// §13: the body goes to every other home node of every group with an
    /// item in the batch, so proofs are available from any of them.
    private func push(_ batch: CommitmentBatch) async {
        guard let peerClient else { return }
        for peer in keeper.pushTargets(batch) {
            guard let client = await peerClient(peer) else { continue }
            do { try await client.pushBatch(batch) } catch { log?("push of batch \(batch.seq) to \(peer.hex.prefix(8)) failed: \(error)") }
        }
    }
}
