import ConvoCore
import ConvoNet
import ConvoNode
import Foundation

/// `convo_node`'s options and runtime. Nodes must offer STUN and TURN
/// (§21): from a TURN service named in the environment (Cloudflare's, say,
/// on Cloud Run), or the built-in relay, which runs when no service is
/// named unless `--no-relay` says otherwise (development only). A node
/// without either advertises `turn=false` and clients rank it last.
public struct NodeOptions: Sendable, Equatable {
    public var port: UInt16 = 8080
    public var publicURL: String?
    public var siteURL: String?
    public var seeds: [String] = []
    public var id: String?
    public var stateDirectory: String?
    public var relay = true
    public var relayHost: String?
    public var turnPort: UInt16 = 3478
    public var relayPorts: ClosedRange<UInt16> = 18100...18199
    /// Witnesses to ask first (§11), before the healthy nodes of the directory.
    public var witnesses: [String] = []
    /// The operator's public key for the descriptor (§24), hex.
    public var operatorPk: String?
    public var commitIntervalMs = Parameters.Node.commitIntervalMs
    /// Seconds a starting instance waits after claiming the state directory
    /// before reading it (`StateLease`).
    public var takeoverSeconds: TimeInterval = 15

    public init() {}

    public static let usage = """
    convo_node [options]
      --port N            HTTP port (env PORT, default 8080)
      --public-url URL    how other nodes and clients reach this node (env CONVO_PUBLIC_URL)
      --site URL          a website to show for this node (env CONVO_SITE_URL)
      --seed URL          another node to learn the directory from (repeatable; env CONVO_SEEDS, comma list)
      --id ID             node id in health reports (env CONVO_NODE_ID; default random)
      --state DIR         where the key, mailbox, log and directory persist (env CONVO_STATE_DIR);
                          on Cloud Run, a Cloud Storage bucket mounted as a volume
      --witness URL       a node to ask to witness this node's log first (repeatable; env CONVO_WITNESSES, comma list)
      --operator HEX      the operator's public key for the node's descriptor (env CONVO_OPERATOR_PK)
      --commit-interval MS  how often to close a batch (env CONVO_COMMIT_INTERVAL_MS; default 300000)
      --takeover SECONDS  wait after claiming the state directory before reading it, so an older
                          instance of this node stops first (env CONVO_TAKEOVER_SECONDS; default 15)
      --no-relay          do not run the built-in STUN/TURN (development only)
      --relay-host HOST   address to advertise for relayed candidates (default: primary IPv4)
      --turn-port N       STUN/TURN port (default 3478)
      --relay-ports A-B   relay socket range (default 18100-18199)

    ICE for /ice comes from the environment when it names a TURN service:
    CLOUDFLARE_TURN_KEY_ID + CLOUDFLARE_TURN_API_TOKEN (Cloudflare Realtime TURN), or
    CONVO_TURN_URLS with CONVO_TURN_USERNAME + CONVO_TURN_CREDENTIAL or CONVO_TURN_SECRET
    (coturn's shared secret). Otherwise the built-in relay serves it. CONVO_STUN_URLS adds STUN.
    Run one instance per node key: two writers to one log equivocate.
    """

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case usage(String)
        public var description: String { switch self { case .usage(let s): return s } }
    }

    public static func parse(_ args: [String], environment env: [String: String] = ProcessInfo.processInfo.environment) throws -> NodeOptions {
        var o = NodeOptions()
        if let p = env["PORT"].flatMap({ UInt16($0) }) { o.port = p }
        o.publicURL = env["CONVO_PUBLIC_URL"]
        o.siteURL = env["CONVO_SITE_URL"]
        o.seeds = (env["CONVO_SEEDS"] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        o.id = env["CONVO_NODE_ID"]
        o.stateDirectory = env["CONVO_STATE_DIR"]
        o.witnesses = (env["CONVO_WITNESSES"] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        o.operatorPk = env["CONVO_OPERATOR_PK"]
        if let ms = env["CONVO_COMMIT_INTERVAL_MS"].flatMap({ UInt64($0) }) { o.commitIntervalMs = ms }
        if let s = env["CONVO_TAKEOVER_SECONDS"].flatMap({ TimeInterval($0) }) { o.takeoverSeconds = s }
        var i = 0
        while i < args.count {
            let a = args[i]
            func value() throws -> String {
                i += 1
                guard i < args.count else { throw Failure.usage("\(a) needs a value") }
                return args[i]
            }
            switch a {
            case "--port": guard let p = UInt16(try value()) else { throw Failure.usage("bad port") }; o.port = p
            case "--public-url": o.publicURL = try value()
            case "--site": o.siteURL = try value()
            case "--seed": o.seeds.append(try value())
            case "--id": o.id = try value()
            case "--state": o.stateDirectory = try value()
            case "--no-relay": o.relay = false
            case "--relay-host": o.relayHost = try value()
            case "--turn-port": guard let p = UInt16(try value()) else { throw Failure.usage("bad turn port") }; o.turnPort = p
            case "--relay-ports":
                let parts = try value().split(separator: "-")
                guard parts.count == 2, let lo = UInt16(parts[0]), let hi = UInt16(parts[1]), lo <= hi else { throw Failure.usage("bad relay ports") }
                o.relayPorts = lo...hi
            case "--witness": o.witnesses.append(try value())
            case "--operator": o.operatorPk = try value()
            case "--commit-interval": guard let ms = UInt64(try value()) else { throw Failure.usage("bad commit interval") }; o.commitIntervalMs = ms
            case "--takeover": guard let s = TimeInterval(try value()) else { throw Failure.usage("bad takeover") }; o.takeoverSeconds = s
            case "-h", "--help": throw Failure.usage(usage)
            default: throw Failure.usage("unknown option \(a)\n" + usage)
            }
            i += 1
        }
        if let op = o.operatorPk, Hash32(hex: op) == nil { throw Failure.usage("--operator takes a 32-byte hex public key") }
        return o
    }
}

/// Peer nodes by key, learned from the directory's URLs (§24): each URL's
/// `/v1/node` says which key it serves.
actor PeerResolver {
    private var clients: [PublicKey: NodeClient] = [:]
    private var tried: Set<String> = []
    let server: ConvoNodeServer
    init(server: ConvoNodeServer) { self.server = server }

    func client(for pk: PublicKey) async -> NodeClient? {
        if let c = clients[pk] { return c }
        for entry in server.knownServers.healthy where !tried.contains(entry.url) {
            tried.insert(entry.url)
            guard let url = URL(string: entry.url) else { continue }
            let c = NodeClient(base: url)
            if let info = try? await c.info(), let key = info.publicKey { clients[key] = c }
        }
        return clients[pk]
    }

    func forget() { tried = [] }
}

/// Witness clients by URL: the configured witnesses first, then the
/// healthy nodes of the directory (§11).
actor WitnessList {
    private var clients: [String: NodeClient] = [:]
    let server: ConvoNodeServer
    let configured: [String]
    init(server: ConvoNodeServer, configured: [String]) { self.server = server; self.configured = configured }

    func list() -> [(url: String, client: NodeClient)] {
        let own = server.configuration.publicURL.flatMap(ServerDirectory.normalize)
        var urls: [String] = []
        for url in configured.compactMap(ServerDirectory.normalize) + server.knownServers.healthy.map(\.url) where url != own && !urls.contains(url) {
            urls.append(url)
        }
        return urls.compactMap { url in
            if let c = clients[url] { return (url, c) }
            guard let base = URL(string: url) else { return nil }
            let c = NodeClient(base: base)
            clients[url] = c
            return (url, c)
        }
    }
}

/// Everything a running node is: the HTTP server, the relay, the ICE
/// provider, the server object, the committer, and the maintenance loop.
public final class NodeRuntime: @unchecked Sendable {
    public let options: NodeOptions
    public let server: ConvoNodeServer
    public let http: PosixHTTPServer
    public let relay: RelayService?
    public let ice: ICEProvider
    public let committer: Committer
    public var log: @Sendable (String) -> Void
    private var maintenance: Thread?
    private var committerTask: Task<Void, Never>?
    private var committerSetup: Task<Void, Never>?

    public init(options: NodeOptions, log: @escaping @Sendable (String) -> Void = { print($0) }) throws {
        self.options = options
        self.log = log
        let id = options.id ?? (0..<8).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        var ice = ICEProvider.fromEnvironment()
        var relay: RelayService?
        if options.relay && !ice.offersTURN {
            let host = options.relayHost ?? NetUtils.primaryIPv4Address() ?? "127.0.0.1"
            let service = RelayService(listenPort: options.turnPort, advertisedHost: host, relayPorts: options.relayPorts)
            do {
                try service.start()
                relay = service
                log("relay: STUN/TURN on \(host):\(options.turnPort), relay ports \(options.relayPorts.lowerBound)-\(options.relayPorts.upperBound)")
                if !ice.offersTURN {
                    ice = ICEProvider(mode: .sharedSecret(urls: service.urls, credentials: service.credentials, ttl: 3600), stunURLs: ice.stunURLs)
                }
            } catch {
                log("relay: failed to start: \(error) (this node does not meet Part III's STUN/TURN requirement)")
            }
        }
        ice.log = log
        ice.start()
        self.ice = ice
        self.relay = relay
        // One writer per key: claim the state directory before reading it.
        var lease: StateLease?
        if let dir = options.stateDirectory {
            let claimed = StateLease(directory: dir)
            log("state: claimed \(dir) as \(claimed.id); waiting \(Int(options.takeoverSeconds))s for any older instance to stop")
            try claimed.claim()
            if options.takeoverSeconds > 0 { Thread.sleep(forTimeInterval: options.takeoverSeconds) }
            guard claimed.confirm() else {
                log("state: a newer instance claimed \(dir) meanwhile; exiting")
                exit(0)
            }
            lease = claimed
        }
        let key = ConvoNodeServer.loadOrCreateKey(stateDirectory: options.stateDirectory)
        let server = ConvoNodeServer(configuration: .init(id: id, publicURL: options.publicURL, site: options.siteURL, seeds: options.seeds,
                                                          stateDirectory: options.stateDirectory,
                                                          operatorPk: options.operatorPk.flatMap { Hash32(hex: $0) }), key: key, ice: ice)
        server.log = log
        server.fetch = { method, url, body in
            if method == "POST" { return HTTPFetch.postJSON(url, body: body ?? Data()) }
            return HTTPFetch.get(url)
        }
        let outbound = DispatchQueue(label: "convo.outbound", qos: .utility)
        server.send = { method, url, body in
            outbound.async {
                let (status, _) = method == "POST" ? HTTPFetch.postJSON(url, body: body ?? Data()) : HTTPFetch.get(url)
                if status < 200 || status >= 300 { log("\(method) \(url) answered \(status)") }
            }
        }
        if let lease {
            server.mayWrite = { lease.holds() }
            server.onLeaseLost = {
                log("state: another instance of this node took over \(lease.path); exiting")
                exit(0)
            }
        }
        self.server = server
        let committer = Committer(nodeKey: key, mailbox: server.mailbox)
        self.committer = committer
        let peers = PeerResolver(server: server)
        let witnesses = WitnessList(server: server, configured: options.witnesses)
        let interval = options.commitIntervalMs
        let setup = Task {
            await committer.setLog(log)
            await committer.setCommitInterval(interval)
            await committer.setPeerClient { pk in await peers.client(for: pk) }
            await committer.setWitnesses { await witnesses.list() }
            if let lease { await committer.setMayWrite { lease.holds() } }
        }
        committerSetup = setup
        committerTask = Task {
            await setup.value
            var n = 0
            while !Task.isCancelled {
                await committer.poll()
                if n % 6 == 0 { await peers.forget() }
                n += 1
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
        http = try PosixHTTPServer(port: options.port) { request in server.respond(to: request) }
    }

    public var nodePk: PublicKey { server.nodePk }

    public func start() {
        http.start()
        var banner = "convo_node \(server.configuration.id) key \(server.nodePk.hex) on :\(options.port)"
        banner += options.publicURL.map { ", public \($0)" } ?? ", no public URL (not advertising)"
        banner += ", ice: \(ice.offersTURN ? "turn" : (ice.stunURLs.isEmpty ? "none" : "stun"))"
        banner += ", seeds: \(options.seeds.count), witnesses: \(options.witnesses.count) configured"
        log(banner)
        let server = self.server
        let thread = Thread {
            while true {
                server.tick()
                Thread.sleep(forTimeInterval: 30)
            }
        }
        thread.start()
        maintenance = thread
    }

    public func stop() {
        http.stop()
        relay?.stop()
        ice.stop()
        committerTask?.cancel()
    }
}
