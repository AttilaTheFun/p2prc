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

/// RFC 9420 §7 — the ratchet tree.
///
/// Members sit at the leaves of a left-balanced binary tree. Every node has a
/// key pair; a member knows the secrets on the path from their leaf to the
/// root, and the root secret is the group's commit secret. To rekey, a member
/// generates fresh secrets up their own path and encrypts each one to the
/// subtree hanging off the other side — so the cost is O(log n) rather than
/// one message per member.
///
/// This is TreeKEM's structure and derivation, with HPKE (RFC 9180) reduced to
/// its DHKEM(X25519)+HKDF-SHA256+AES-128-GCM instantiation written directly
/// against swift-crypto. All the primitives are Apple's; none are hand-rolled.
public struct RatchetTree {
    /// Nodes are stored in the array layout the spec uses: leaves at even
    /// indices, parents at odd ones.
    public struct Node {
        public var publicKey: Curve25519.KeyAgreement.PublicKey?
        public var privateKey: Curve25519.KeyAgreement.PrivateKey?
        /// Leaves carry a member; parents don't.
        public var member: String?
        public var blank: Bool { publicKey == nil }
    }

    public var nodes: [Node]

    public init(leafCount: Int) {
        // RFC 9420 §4.1: the ratchet tree is a *complete* binary tree, so the
        // leaf count is rounded up to a power of two and the surplus leaves
        // are left blank. The parent/sibling arithmetic below depends on it.
        var padded = 1
        while padded < max(leafCount, 1) { padded <<= 1 }
        let size = 2 * padded - 1
        nodes = Array(repeating: Node(publicKey: nil, privateKey: nil, member: nil), count: size)
    }

    public var leafCount: Int { (nodes.count + 1) / 2 }

    public static func leafIndex(_ leaf: Int) -> Int { 2 * leaf }

    /// RFC 9420 §4.2: the parent of a node in the array layout.
    static func parent(_ index: Int, size: Int) -> Int? {
        if index == root(size: size) { return nil }
        let k = level(index)
        let bit = (index >> (k + 1)) & 1
        return bit == 0 ? index + (1 << k) : index - (1 << k)
    }

    static func level(_ index: Int) -> Int {
        if index & 1 == 0 { return 0 }
        var k = 0
        while ((index >> k) & 1) == 1 { k += 1 }
        return k
    }

    static func root(size: Int) -> Int {
        var r = 1
        while r <= size { r <<= 1 }
        return (r >> 1) - 1
    }

    static func sibling(_ index: Int, size: Int) -> Int? {
        guard let p = parent(index, size: size) else { return nil }
        return index < p ? p + (p - index) : p - (index - p)
    }

    /// The nodes from a leaf up to the root, exclusive of the leaf itself.
    public static func directPath(leaf: Int, size: Int) -> [Int] {
        var path: [Int] = []
        var current = leafIndex(leaf)
        while let p = parent(current, size: size) {
            path.append(p)
            current = p
        }
        return path
    }

    /// The siblings hanging off that path — the subtrees a new path secret has
    /// to be encrypted to.
    public static func copath(leaf: Int, size: Int) -> [Int] {
        var path: [Int] = []
        var current = leafIndex(leaf)
        while let p = parent(current, size: size) {
            if let s = sibling(current, size: size) { path.append(s) }
            current = p
        }
        return path
    }

    /// Every non-blank node in a subtree — who must be able to decrypt.
    public func resolution(_ index: Int) -> [Int] {
        if !nodes[index].blank { return [index] }
        if RatchetTree.level(index) == 0 { return [] }
        let k = RatchetTree.level(index)
        let left = index - (1 << (k - 1))
        let right = index + (1 << (k - 1))
        guard left >= 0, right < nodes.count else { return [] }
        return resolution(left) + resolution(right)
    }

    /// Installs a private key we hold for a node — our own leaf, normally.
    public mutating func setPrivateKey(_ key: Curve25519.KeyAgreement.PrivateKey, atLeaf leaf: Int) {
        let index = RatchetTree.leafIndex(leaf)
        guard index < nodes.count else { return }
        nodes[index].privateKey = key
    }

    public mutating func setLeaf(_ leaf: Int, member: String, publicKey: Curve25519.KeyAgreement.PublicKey) {
        let index = RatchetTree.leafIndex(leaf)
        guard index < nodes.count else { return }
        nodes[index].member = member
        nodes[index].publicKey = publicKey
    }

    public mutating func blankPath(from leaf: Int) {
        for index in RatchetTree.directPath(leaf: leaf, size: nodes.count) {
            nodes[index] = Node(publicKey: nil, privateKey: nil, member: nil)
        }
    }

    public func leafIndex(ofMember member: String) -> Int? {
        for leaf in 0..<leafCount {
            let index = RatchetTree.leafIndex(leaf)
            if index < nodes.count, nodes[index].member == member { return leaf }
        }
        return nil
    }

    public var members: [String] {
        (0..<leafCount).compactMap { leaf in
            let index = RatchetTree.leafIndex(leaf)
            return index < nodes.count ? nodes[index].member : nil
        }
    }

    /// RFC 9420 §7.4: a path secret is expanded into the next path secret and
    /// the node's key pair.
    static func deriveKeyPair(from pathSecret: SymmetricKey)
        -> (node: SymmetricKey, keyPair: Curve25519.KeyAgreement.PrivateKey)
    {
        let nodeSecret = KeySchedule.deriveSecret(secret: pathSecret, label: "node")
        let seed = nodeSecret.withUnsafeBytes { Array($0) }
        // A 32-byte seed is exactly an X25519 private key.
        let key = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(seed))
        return (nodeSecret, key)
    }

    static func nextPathSecret(_ secret: SymmetricKey) -> SymmetricKey {
        KeySchedule.deriveSecret(secret: secret, label: "path")
    }

    /// An UpdatePath: fresh secrets up the committer's path, each encrypted to
    /// the resolution of the corresponding copath node.
    public struct UpdatePath {
        public struct Step {
            public let node: Int
            public let publicKey: Data
            /// Encrypted copies of the path secret, one per recipient node.
            public let encrypted: [(to: Int, kem: Data, ciphertext: Data)]

            public init(node: Int, publicKey: Data, encrypted: [(to: Int, kem: Data, ciphertext: Data)]) {
                self.node = node
                self.publicKey = publicKey
                self.encrypted = encrypted
            }
        }
        public let leaf: Int
        public let leafPublicKey: Data
        public let steps: [Step]
        /// The root secret this path produces — the commit secret. Author-only:
        /// nil on a path decoded from the wire, where it is precisely the thing
        /// a recipient must *derive* rather than be told.
        public let commitSecret: SymmetricKey?
        /// The committer's own path secrets: the leaf's, then one per step.
        /// These are author-local and never go on the wire — every other
        /// member learns their portion from `encrypted` instead. Keeping them
        /// is what lets the author re-apply their own commit deterministically
        /// (after a rollback), rather than having to draw a fresh random path.
        public let ownSecrets: [SymmetricKey]

        public init(
            leaf: Int,
            leafPublicKey: Data,
            steps: [Step],
            commitSecret: SymmetricKey? = nil,
            ownSecrets: [SymmetricKey] = []
        ) {
            self.leaf = leaf
            self.leafPublicKey = leafPublicKey
            self.steps = steps
            self.commitSecret = commitSecret
            self.ownSecrets = ownSecrets
        }
    }

    /// Re-applies a path we authored. Deterministic, so the author can run it
    /// as many times as needed and land on exactly the tree everyone else has.
    public mutating func applyOwnPath(_ path: UpdatePath) {
        guard let leafSecret = path.ownSecrets.first else { return }
        let leafKey = RatchetTree.deriveKeyPair(from: leafSecret).keyPair
        nodes[RatchetTree.leafIndex(path.leaf)].publicKey = leafKey.publicKey
        nodes[RatchetTree.leafIndex(path.leaf)].privateKey = leafKey
        for (position, step) in path.steps.enumerated() where position + 1 < path.ownSecrets.count {
            let derived = RatchetTree.deriveKeyPair(from: path.ownSecrets[position + 1])
            nodes[step.node].publicKey = derived.keyPair.publicKey
            nodes[step.node].privateKey = derived.keyPair
        }
    }

    /// Generates a new path from `leaf`, updating this tree in place.
    public mutating func updatePath(from leaf: Int, groupContext: [UInt8]) throws -> UpdatePath {
        var pathSecret = SymmetricKey(size: .bits256)
        let leafKey = RatchetTree.deriveKeyPair(from: pathSecret).keyPair
        nodes[RatchetTree.leafIndex(leaf)].publicKey = leafKey.publicKey
        nodes[RatchetTree.leafIndex(leaf)].privateKey = leafKey

        let direct = RatchetTree.directPath(leaf: leaf, size: nodes.count)
        let co = RatchetTree.copath(leaf: leaf, size: nodes.count)
        var steps: [UpdatePath.Step] = []
        var ownSecrets: [SymmetricKey] = [pathSecret]

        for (position, node) in direct.enumerated() {
            pathSecret = RatchetTree.nextPathSecret(pathSecret)
            ownSecrets.append(pathSecret)
            let derived = RatchetTree.deriveKeyPair(from: pathSecret)
            nodes[node].publicKey = derived.keyPair.publicKey
            nodes[node].privateKey = derived.keyPair

            var encrypted: [(to: Int, kem: Data, ciphertext: Data)] = []
            if position < co.count {
                for recipient in resolution(co[position]) {
                    guard let recipientKey = nodes[recipient].publicKey else { continue }
                    let sealed = try MLSHPKE.seal(
                        to: recipientKey,
                        plaintext: pathSecret.withUnsafeBytes { Data($0) },
                        info: groupContext
                    )
                    encrypted.append((to: recipient, kem: sealed.kem, ciphertext: sealed.ciphertext))
                }
            }
            steps.append(UpdatePath.Step(
                node: node,
                publicKey: derived.keyPair.publicKey.rawRepresentation,
                encrypted: encrypted
            ))
        }

        // The last path secret is the root's; it becomes the commit secret.
        let commitSecret = KeySchedule.deriveSecret(secret: pathSecret, label: "commit")
        return UpdatePath(
            leaf: leaf,
            leafPublicKey: leafKey.publicKey.rawRepresentation,
            steps: steps,
            commitSecret: commitSecret,
            ownSecrets: ownSecrets
        )
    }

    /// Applies someone else's UpdatePath, recovering the commit secret if any
    /// step was encrypted to a node we hold a private key for.
    public mutating func applyUpdatePath(
        _ path: UpdatePath,
        as leaf: Int,
        groupContext: [UInt8]
    ) throws -> SymmetricKey? {
        nodes[RatchetTree.leafIndex(path.leaf)].publicKey =
            try Curve25519.KeyAgreement.PublicKey(rawRepresentation: path.leafPublicKey)

        var recovered: SymmetricKey?
        for step in path.steps {
            nodes[step.node].publicKey =
                try Curve25519.KeyAgreement.PublicKey(rawRepresentation: step.publicKey)

            if recovered == nil {
                for entry in step.encrypted {
                    guard let privateKey = nodes[entry.to].privateKey else { continue }
                    if let opened = try? MLSHPKE.open(
                        with: privateKey, kem: entry.kem,
                        ciphertext: entry.ciphertext, info: groupContext
                    ) {
                        recovered = SymmetricKey(data: opened)
                        break
                    }
                }
            } else {
                // Once we are on the path, later secrets follow by derivation.
                recovered = RatchetTree.nextPathSecret(recovered!)
            }
            if let secret = recovered {
                let derived = RatchetTree.deriveKeyPair(from: secret)
                nodes[step.node].privateKey = derived.keyPair
            }
        }
        guard let rootSecret = recovered else { return nil }
        return KeySchedule.deriveSecret(secret: rootSecret, label: "commit")
    }
}

/// HPKE for MLS ciphersuite 0x0001, which is swift-crypto's own RFC 9180
/// implementation configured to the exact triple the suite names:
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
///
/// This deliberately calls Apple's HPKE rather than assembling one out of
/// X25519 + HKDF + AES-GCM. The pieces are the same, but the key schedule
/// between them is where RFC 9180 puts its domain separation, and an
/// implementation that gets that subtly wrong still encrypts and decrypts
/// perfectly against itself — it just isn't HPKE, and isn't interoperable.
public enum MLSHPKE {
    /// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519's HPKE parameters.
    // Linux swift-crypto's HPKE.Ciphersuite is not Sendable; the value is
    // immutable configuration.
    nonisolated(unsafe) static let ciphersuite = HPKE.Ciphersuite(
        kem: .Curve25519_HKDF_SHA256,
        kdf: .HKDF_SHA256,
        aead: .AES_GCM_128
    )

    public static func seal(
        to recipient: Curve25519.KeyAgreement.PublicKey,
        plaintext: Data,
        info: [UInt8]
    ) throws -> (kem: Data, ciphertext: Data) {
        var sender = try HPKE.Sender(
            recipientKey: recipient,
            ciphersuite: ciphersuite,
            info: Data(info)
        )
        let ciphertext = try sender.seal(plaintext)
        return (sender.encapsulatedKey, ciphertext)
    }

    public static func open(
        with privateKey: Curve25519.KeyAgreement.PrivateKey,
        kem: Data,
        ciphertext: Data,
        info: [UInt8]
    ) throws -> Data {
        var recipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: ciphersuite,
            info: Data(info),
            encapsulatedKey: kem
        )
        return try recipient.open(ciphertext)
    }

    // MARK: - Authenticated mode (RFC 9180, mode_auth)
    //
    // Auth mode binds the *sender's* static key into the KEM: opening only
    // succeeds if the ciphertext really came from the holder of that key.
    // This is what lets a reconnect offer be trusted without signatures —
    // X25519 keys cannot sign, but with HPKE they can still prove authorship
    // to a peer who already knows them.

    public static func sealAuth(
        from sender: Curve25519.KeyAgreement.PrivateKey,
        to recipient: Curve25519.KeyAgreement.PublicKey,
        plaintext: Data,
        info: [UInt8]
    ) throws -> (kem: Data, ciphertext: Data) {
        var hpkeSender = try HPKE.Sender(
            recipientKey: recipient,
            ciphersuite: ciphersuite,
            info: Data(info),
            authenticatedBy: sender
        )
        let ciphertext = try hpkeSender.seal(plaintext)
        return (hpkeSender.encapsulatedKey, ciphertext)
    }

    public static func openAuth(
        with privateKey: Curve25519.KeyAgreement.PrivateKey,
        from sender: Curve25519.KeyAgreement.PublicKey,
        kem: Data,
        ciphertext: Data,
        info: [UInt8]
    ) throws -> Data {
        var recipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: ciphersuite,
            info: Data(info),
            encapsulatedKey: kem,
            authenticatedBy: sender
        )
        return try recipient.open(ciphertext)
    }
}
