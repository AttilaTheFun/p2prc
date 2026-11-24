import Crypto
// FoundationEssentials has everything this file needs (Data, JSON, Date)
// without FoundationInternationalization — whose embedded ICU tables are
// ~33 MB of wasm data section. One plain `import Foundation` anywhere in the
// module graph pulls them back in.
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// An MLS group, with the one adaptation true peer-to-peer requires.
///
/// RFC 9420 demands a single agreed Commit per epoch: everyone must apply the
/// same sequence, and a fork is an error rather than something to tolerate.
/// Deployments normally get that ordering from a Delivery Service. We have no
/// server — but we do have a content-addressed event graph that every member
/// orders identically, so the *group itself* can decide:
///
///   for a given epoch, the candidate commit with the lowest id wins;
///   every other commit from that epoch is rejected, and its author
///   re-issues their proposals against the new epoch.
///
/// Every member reaches that verdict independently and identically, so the
/// group stays linear — in spec — without anyone arbitrating. The cost is a
/// retry when two people commit at once, not a server.
public final class MLSGroup {
    public struct Member: Equatable {
        public let id: String
        public let name: String
        public let publicKey: Data

        public init(id: String, name: String, publicKey: Data) {
            self.id = id
            self.name = name
            self.publicKey = publicKey
        }
    }

    public struct Commit {
        /// Content-addressed id; also the tiebreak for concurrent commits.
        public let id: String
        public let epoch: UInt64
        public let committer: String
        public let path: RatchetTree.UpdatePath
        public let members: [Member]
        /// The path's leaf secret sealed (HPKE) to the committer's own leaf
        /// key, so another device holding the same leaf can apply this
        /// commit as its author would; nobody else can open it, and it
        /// tells the others nothing they are not already told.
        public let ownSealed: (kem: Data, ciphertext: Data)?

        public init(
            id: String,
            epoch: UInt64,
            committer: String,
            path: RatchetTree.UpdatePath,
            members: [Member],
            ownSealed: (kem: Data, ciphertext: Data)? = nil
        ) {
            self.id = id
            self.epoch = epoch
            self.committer = committer
            self.path = path
            self.members = members
            self.ownSealed = ownSealed
        }
    }

    public let groupID: String
    public private(set) var epoch: UInt64 = 0
    public private(set) var tree: RatchetTree
    public private(set) var members: [Member] = []
    public private(set) var secrets: KeySchedule.EpochSecrets?
    /// The winning commit id per epoch, so a late-arriving rival is rejected
    /// rather than forking the group.
    public private(set) var acceptedCommits: [UInt64: String] = [:]

    private let selfID: String
    private var selfKey: Curve25519.KeyAgreement.PrivateKey
    private var senderRatchets: [String: (secret: SymmetricKey, generation: UInt32)] = [:]

    /// Enough of the previous epoch to undo the current one, should a
    /// lower-id commit for it arrive late.
    private struct Rollback {
        let epoch: UInt64
        let secrets: KeySchedule.EpochSecrets?
    }
    private var rollbackState: Rollback?
    /// The commit secret of the current epoch, kept so a group can be
    /// restored from storage without replaying the commit (`restore`).
    public private(set) var lastCommitSecret: SymmetricKey?
    /// How many application messages this member has sealed in the epoch:
    /// restore must ratchet past them or AES-GCM nonces would repeat.
    public var ownGeneration: UInt32 { senderRatchets[selfID]?.generation ?? 0 }
    /// Domain separation for the leaf secret sealed to the committer's own key.
    static let ownSealInfo = Array("convo/mls/own-commit".utf8)

    /// Moves this member's ratchet past `generation` when it is not already:
    /// another device holding the same leaf sealed there, and sealing at a
    /// generation twice would reuse a key and nonce.
    public func noteOwnGeneration(past generation: UInt32) {
        var state = ratchet(for: selfID)
        guard state.generation <= generation else { return }
        while state.generation <= generation {
            let step = KeySchedule.ratchetStep(secret: state.secret, generation: state.generation)
            state = (step.next, state.generation + 1)
        }
        senderRatchets[selfID] = state
    }
    public var selfMemberID: String { selfID }

    /// Rebuilds the epoch from its commit secret and roster (membership
    /// is fixed for a Convo group, so one epoch is the whole life of it)
    /// and advances this member's ratchet to `ownGeneration`.
    public func restore(epoch: UInt64, commitSecret: SymmetricKey, roster: [Member], ownGeneration: UInt32) {
        (tree, members) = builtTree(with: roster)
        self.epoch = epoch
        lastCommitSecret = commitSecret
        secrets = KeySchedule.nextEpoch(
            initSecret: SymmetricKey(data: Data(repeating: 0, count: MLSCipherSuite.hashLength)),
            commitSecret: commitSecret,
            groupContext: groupContext()
        )
        senderRatchets.removeAll()
        var state = ratchet(for: selfID)
        while state.generation < ownGeneration {
            let step = KeySchedule.ratchetStep(secret: state.secret, generation: state.generation)
            state = (step.next, state.generation + 1)
        }
        senderRatchets[selfID] = state
    }

    public init(groupID: String, selfID: String, selfKey: Curve25519.KeyAgreement.PrivateKey) {
        self.groupID = groupID
        self.selfID = selfID
        self.selfKey = selfKey
        tree = RatchetTree(leafCount: 1)
    }

    /// RFC 9420 §8.1: the GroupContext binds every derivation to this group,
    /// epoch and membership, so secrets can't be replayed into another.
    public func groupContext() -> [UInt8] {
        context(epoch: epoch, members: members)
    }

    private func context(epoch: UInt64, members: [Member]) -> [UInt8] {
        var context: [UInt8] = []
        context += Array(groupID.utf8)
        withUnsafeBytes(of: epoch.bigEndian) { context += Array($0) }
        // Tree hash stand-in: the ordered member list commits to membership.
        context += Array(members.map(\.id).sorted().joined(separator: ",").utf8)
        return context
    }

    // MARK: - Membership

    /// Builds the tree a roster implies, without touching group state. Every
    /// member runs this over the same roster and gets the same tree, which is
    /// what lets a commit be applied — or re-applied after a rollback — from
    /// nothing but the roster and the update path.
    private func builtTree(with roster: [Member]) -> (RatchetTree, [Member]) {
        let sorted = roster.sorted { $0.id < $1.id }
        var tree = RatchetTree(leafCount: max(sorted.count, 1))
        for (leaf, member) in sorted.enumerated() {
            guard let key = try? Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: member.publicKey
            ) else { continue }
            tree.setLeaf(leaf, member: member.id, publicKey: key)
        }
        if let leaf = tree.leafIndex(ofMember: selfID) {
            tree.setPrivateKey(selfKey, atLeaf: leaf)
        }
        return (tree, sorted)
    }

    public func rebuildTree(with roster: [Member]) throws {
        (tree, members) = builtTree(with: roster)
    }

    // MARK: - Commits

    /// Produces a commit advancing the group by one epoch. `id` is supplied by
    /// the caller (the event id), which is what makes ordering deterministic.
    ///
    /// This does not mutate the group: a commit may lose the race for its
    /// epoch, and a proposal that loses must leave no trace. The state change
    /// happens in `apply`, which the author calls on its own commit like
    /// anyone else.
    public func createCommit(id: String, roster: [Member]) throws -> Commit {
        var (candidate, sorted) = builtTree(with: roster)
        guard let leaf = candidate.leafIndex(ofMember: selfID) else {
            throw MLSError("we are not a member of this group")
        }
        let groupContext = context(epoch: epoch, members: sorted)
        let path = try candidate.updatePath(from: leaf, groupContext: groupContext)
        var ownSealed: (kem: Data, ciphertext: Data)?
        if let leafSecret = path.ownSecrets.first {
            ownSealed = try MLSHPKE.seal(to: selfKey.publicKey, plaintext: leafSecret.withUnsafeBytes { Data($0) }, info: Self.ownSealInfo + groupContext)
        }
        return Commit(id: id, epoch: epoch + 1, committer: selfID, path: path, members: sorted, ownSealed: ownSealed)
    }

    public enum CommitOutcome: Equatable {
        case applied(UInt64)
        /// A rival commit for the same epoch already won; re-issue yours.
        case supersededBy(String)
        case stale
        case notForUs
    }

    /// Applies a commit, enforcing one commit per epoch.
    @discardableResult
    public func apply(_ commit: Commit, isOwn: Bool = false) throws -> CommitOutcome {
        if let winner = acceptedCommits[commit.epoch] {
            // Lowest id wins. If the winner is already applied and a *lower*
            // id turns up afterwards, first-arrival must not decide the
            // outcome — so we revert that epoch and apply the rival instead.
            // Every member does this, so they all converge on the same commit
            // no matter what order the network delivered them in.
            guard commit.id < winner else { return .supersededBy(winner) }
            guard commit.epoch == epoch, let rollback = rollbackState else { return .stale }
            epoch = rollback.epoch
            secrets = rollback.secrets
            acceptedCommits[commit.epoch] = nil
            senderRatchets.removeAll()
        }
        guard commit.epoch == epoch + 1 else {
            // Already past this epoch, or too far ahead to apply in order.
            return .stale
        }

        // Applied against a *copy*, so a commit that turns out not to be for
        // us can't leave the group's tree half-rebuilt.
        var candidate = tree
        var candidateMembers = members
        var commitSecret: SymmetricKey?
        if isOwn {
            (candidate, candidateMembers) = builtTree(with: commit.members)
            candidate.applyOwnPath(commit.path)
            guard let own = commit.path.commitSecret else {
                throw MLSError("own commit is missing its commit secret")
            }
            commitSecret = own
        } else if commit.committer == selfID {
            // Our own leaf committed on another device: open the leaf secret
            // it sealed to us and walk the path as the author did.
            (candidate, candidateMembers) = builtTree(with: commit.members)
            guard let sealed = commit.ownSealed,
                  let opened = try? MLSHPKE.open(with: selfKey, kem: sealed.kem, ciphertext: sealed.ciphertext,
                                                 info: Self.ownSealInfo + context(epoch: epoch, members: candidateMembers)) else { return .notForUs }
            var secret = SymmetricKey(data: opened)
            var ownSecrets = [secret]
            for _ in commit.path.steps {
                secret = RatchetTree.nextPathSecret(secret)
                ownSecrets.append(secret)
            }
            let path = RatchetTree.UpdatePath(leaf: commit.path.leaf, leafPublicKey: commit.path.leafPublicKey, steps: commit.path.steps,
                                              commitSecret: KeySchedule.deriveSecret(secret: secret, label: "commit"), ownSecrets: ownSecrets)
            candidate.applyOwnPath(path)
            commitSecret = path.commitSecret
        } else {
            (candidate, candidateMembers) = builtTree(with: commit.members)
            if let leaf = candidate.leafIndex(ofMember: selfID) {
                commitSecret = try candidate.applyUpdatePath(
                    commit.path, as: leaf, groupContext: context(epoch: epoch, members: candidateMembers)
                )
            }
        }
        guard let secret = commitSecret else { return .notForUs }

        let previousInit = secrets?.initSecret
            ?? SymmetricKey(data: Data(repeating: 0, count: MLSCipherSuite.hashLength))
        rollbackState = Rollback(epoch: epoch, secrets: secrets)
        lastCommitSecret = secret
        tree = candidate
        members = candidateMembers
        epoch = commit.epoch
        secrets = KeySchedule.nextEpoch(
            initSecret: previousInit,
            commitSecret: secret,
            groupContext: groupContext()
        )
        acceptedCommits[commit.epoch] = commit.id
        senderRatchets.removeAll()
        return .applied(epoch)
    }

    // MARK: - Application messages

    /// RFC 9420 §9: each sender ratchets their own chain, so every message
    /// gets a fresh key that is then discarded — forward secrecy within an
    /// epoch, not merely between epochs.
    private func ratchet(for sender: String) -> (secret: SymmetricKey, generation: UInt32) {
        if let existing = senderRatchets[sender] { return existing }
        guard let encryption = secrets?.encryptionSecret else {
            return (SymmetricKey(size: .bits256), 0)
        }
        let base = KeySchedule.expandWithLabel(
            secret: encryption, label: "sender", context: Array(sender.utf8),
            length: MLSCipherSuite.hashLength
        )
        let fresh = (secret: base, generation: UInt32(0))
        senderRatchets[sender] = fresh
        return fresh
    }

    public struct Sealed {
        public let epoch: UInt64
        public let sender: String
        public let generation: UInt32
        public let ciphertext: Data

        public init(epoch: UInt64, sender: String, generation: UInt32, ciphertext: Data) {
            self.epoch = epoch
            self.sender = sender
            self.generation = generation
            self.ciphertext = ciphertext
        }
    }

    public func seal(_ plaintext: String) throws -> Sealed {
        guard secrets != nil else { throw MLSError("group has no epoch secrets yet") }
        var state = ratchet(for: selfID)
        let step = KeySchedule.ratchetStep(secret: state.secret, generation: state.generation)
        let sealed = try AES.GCM.seal(
            Data(plaintext.utf8),
            using: step.key,
            nonce: AES.GCM.Nonce(data: step.nonce),
            authenticating: Data(groupContext())
        )
        let generation = state.generation
        state = (secret: step.next, generation: generation + 1)
        senderRatchets[selfID] = state
        return Sealed(
            epoch: epoch,
            sender: selfID,
            generation: generation,
            ciphertext: sealed.ciphertext + sealed.tag
        )
    }

    public func open(_ message: Sealed) throws -> String {
        guard message.epoch == epoch, let encryption = secrets?.encryptionSecret else {
            throw MLSError("no keys for epoch \(message.epoch)")
        }
        // Derive that sender's chain forward to the message's generation.
        var secret = KeySchedule.expandWithLabel(
            secret: encryption, label: "sender", context: Array(message.sender.utf8),
            length: MLSCipherSuite.hashLength
        )
        var step = KeySchedule.ratchetStep(secret: secret, generation: 0)
        var generation: UInt32 = 0
        while generation < message.generation {
            secret = step.next
            generation += 1
            step = KeySchedule.ratchetStep(secret: secret, generation: generation)
        }
        // Re-based into a fresh Data: `prefix`/`suffix(from:)` on a Data slice
        // are absolute-index operations, and CryptoKit hands back slices whose
        // startIndex is not necessarily zero.
        let bytes = Data(message.ciphertext)
        guard bytes.count >= 16 else { throw MLSError("ciphertext too short") }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: step.nonce),
            ciphertext: bytes.dropLast(16),
            tag: bytes.suffix(16)
        )
        let opened = try AES.GCM.open(box, using: step.key, authenticating: Data(groupContext()))
        return String(decoding: opened, as: UTF8.self)
    }
}

public struct MLSError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { "MLS error: \(message)" }
}
