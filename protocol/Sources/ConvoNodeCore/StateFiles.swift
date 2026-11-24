import ConvoFoundation

/// How the node writes its state files. On a local disk each write goes to a
/// temporary file renamed into place, so a crash never leaves half a file.
/// On an object store mounted as a file system (Cloud Storage FUSE on Cloud
/// Run) an upload already replaces the object whole, and every rename and
/// directory probe is a billed operation, so `objectStore` writes in place
/// and each directory is created once per process (§26).
public enum StateFiles {
    /// `CONVO_STATE_OBJECT_STORE=1`: the state directory is an object store.
    public static let objectStore = ProcessInfo.processInfo.environment["CONVO_STATE_OBJECT_STORE"] == "1"

    /// The directories this process has made; a lock guards the set.
    private final class Made: @unchecked Sendable {
        let lock = NSLock()
        var dirs: Set<String> = []
    }
    private static let made = Made()

    /// Writes `data` to `path`, creating its directory first if this process
    /// hasn't yet.
    public static func write(_ data: Data, to path: String) throws {
        let dir = parent(of: path)
        made.lock.lock()
        let known = made.dirs.contains(dir)
        made.lock.unlock()
        if !known {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            made.lock.lock(); made.dirs.insert(dir); made.lock.unlock()
        }
        try data.write(to: URL(fileURLWithPath: path), options: writeOptions)
    }

    /// WASI has no temporary files, so no atomic writes; its hosts keep a
    /// file whole until it's closed (a Durable Object stores it in one row).
    private static var writeOptions: Data.WritingOptions {
        #if os(WASI)
        return []
        #else
        return objectStore ? [] : .atomic
        #endif
    }

    public static func write(_ bytes: [UInt8], to path: String) throws { try write(Data(bytes), to: path) }

    /// The directory a path is in.
    public static func parent(of path: String) -> String {
        guard let slash = path.lastIndex(of: "/") else { return "." }
        return slash == path.startIndex ? "/" : String(path[..<slash])
    }

    /// Readable by the owner only (the node key), where the platform has
    /// permissions: not Windows, not WASI.
    public static func restrict(_ path: String) {
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }
}
