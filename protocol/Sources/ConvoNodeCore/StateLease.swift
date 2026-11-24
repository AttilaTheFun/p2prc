import ConvoCore
import ConvoFoundation

/// One writer per node key (spec §26, §28): a node's log must have one
/// author, or it signs two histories (F6). A platform may run two instances
/// of one node for a while (Cloud Run treats `--max-instances 1` as a
/// ceiling it can briefly exceed), so the instances settle it through the
/// data directory they share: the newest claim wins.
///
/// A starting instance writes its claim to `<state>/owner`, then waits
/// `takeover` before reading any state, so an older instance has time to see
/// the claim and stop. Every write path calls `holds()`, which re-reads the
/// file at most every `recheck`; an instance that finds another's claim
/// there has lost the lease and must stop writing. The directory must show
/// other writers' changes promptly (on Cloud Storage FUSE, mount it with
/// `metadata-cache-ttl-secs=0`).
public final class StateLease: @unchecked Sendable {
    public let path: String
    public let id: String
    public let recheck: TimeInterval
    private let lock = NSLock()
    private var lastCheck: Date = .distantPast
    private var held = true

    public init(directory: String, id: String = (0..<16).map { _ in UInt8.random(in: 0...255) }.hex,
                recheck: TimeInterval = 10) {
        self.path = directory + "/owner"
        self.id = id
        self.recheck = recheck
    }

    /// Writes this instance's claim. The caller then waits the takeover time
    /// for an older holder to notice, and calls `confirm`.
    public func claim() throws {
        try FileManager.default.createDirectory(atPath: StateFiles.parent(of: path), withIntermediateDirectories: true)
        try Data("\(id) \(Int(Date().timeIntervalSince1970))\n".utf8).write(to: URL(fileURLWithPath: path))
    }

    /// After the takeover wait: whether the claim still stands.
    public func confirm() -> Bool {
        lock.lock(); lastCheck = .distantPast; lock.unlock()
        return holds()
    }

    /// Whether this instance still holds the lease; once lost, never again.
    public func holds() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard held else { return false }
        guard Date().timeIntervalSince(lastCheck) >= recheck else { return true }
        lastCheck = Date()
        // An unreadable file (a write in flight) is not a loss; a readable
        // claim by someone else is.
        guard let data = FileManager.default.contents(atPath: path) else { return true }
        let owner = String(decoding: data, as: UTF8.self).split(separator: " ").first.map(String.init)
        if let owner, !owner.isEmpty, owner != id { held = false }
        return held
    }
}
