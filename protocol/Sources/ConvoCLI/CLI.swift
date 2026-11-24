import ConvoClient
import ConvoCore
import ConvoNet
import Foundation

/// The reference CLI (§0): every protocol action as a command, on a
/// store directory, against nodes given by URL. A library, so the
/// end-to-end tests drive it in process.
public struct ConvoCLI: Sendable {
    public struct Options: Sendable {
        public var stateDirectory: String
        public var nodes: [String] = []
        public var name: String?
        public var minHosts: Int?
        public var maxHosts: Int?
        public init(stateDirectory: String) { self.stateDirectory = stateDirectory }
    }

    public enum Failure: Error, CustomStringConvertible {
        case usage(String), badArgument(String), notFound(String)
        public var description: String {
            switch self {
            case .usage(let s): return "usage: \(s)"
            case .badArgument(let s): return "bad argument: \(s)"
            case .notFound(let s): return "not found: \(s)"
            }
        }
    }

    public static let usage = """
    convo [--state DIR] [--node URL]... [--name NAME] <command>
      identity [--new | --phrase "WORDS" | --secret KEY]   this identity: show, create, or import (hex secret)
      publish                          publish the identity record and KeyPackage (§13.2)
      nodes                            known nodes and their health
      create ID... [--salt HEX]        invite identities (hex); prints the salt
      complete SALT                    creator: collect announces, send genesis, hand it to the home nodes
      join SALT                        member: answer an invite / take the genesis
      groups                           groups held
      send GROUP TEXT                  seal, sign, publish to every healthy host
      pull GROUP                       fetch from hosts, verify, ack; detect fraud
      show GROUP                       canonical history with states (§9.4 display)
      attest GROUP                     sign the head and publish the attestation
      commitments GROUP                resolve commitment refs from the hosts; F4 when a promise was broken
      checkpoint NODE_PK               the newest witnessed checkpoint of a node's log the known nodes hold
      fork GROUP [--reason R] [--at HEAD] [ID...]
                                       begin a fork (membership|recovery|rotation|host) at a committed attested head
      republish PARENT CHILD           republish own committed messages past the fork point into CHILD (§9.4)
      rebase PARENT CHILD              re-send own uncommitted parent messages in CHILD (§9.6)
      probe GROUP ITEM NODE            fetch one receipted item; F1/F3 if the node lies
      fraud                            fraud proofs built so far
      hosts GROUP                      the group's hosts and whether a host-change fork is due
    Options: --min-hosts N / --max-hosts N override the §13.1 client bounds (development).
    Environment: CONVO_STATE (default ~/.convo), CONVO_NODES (comma list).
    """

    public let options: Options
    /// How the node directory is built; tests point it at in-process nodes.
    public let directoryFactory: (@Sendable () async -> NodeDirectory)?

    public init(options: Options, directoryFactory: (@Sendable () async -> NodeDirectory)? = nil) {
        self.options = options
        self.directoryFactory = directoryFactory
    }

    /// Parses argv (without the program name); returns options and the
    /// remaining command words.
    public static func parse(_ args: [String], environment env: [String: String] = ProcessInfo.processInfo.environment) throws -> (Options, [String]) {
        var options = Options(stateDirectory: env["CONVO_STATE"] ?? (NSHomeDirectory() + "/.convo"))
        options.nodes = (env["CONVO_NODES"] ?? "").split(separator: ",").map(String.init).filter { !$0.isEmpty }
        var rest: [String] = []
        var i = 0
        while i < args.count {
            let a = args[i]
            func value() throws -> String {
                i += 1
                guard i < args.count else { throw Failure.usage("\(a) needs a value") }
                return args[i]
            }
            switch a {
            case "--state": options.stateDirectory = try value()
            case "--node": options.nodes.append(try value())
            case "--name": options.name = try value()
            case "--min-hosts": options.minHosts = Int(try value())
            case "--max-hosts": options.maxHosts = Int(try value())
            case "-h", "--help": throw Failure.usage(usage)
            default: rest.append(a)
            }
            i += 1
        }
        return (options, rest)
    }

    private func loadIdentity(words: [String]) -> [String]? { words.isEmpty ? nil : words }

    /// The client for this store: identity from the store (created on
    /// first use, with its recovery phrase saved once), nodes from the
    /// options and the store.
    public func client(newIdentity: ConvoIdentity? = nil, phrase: [String]? = nil) async throws -> ConvoClient {
        let store = ClientStore(directory: options.stateDirectory)
        var identity = newIdentity ?? store.loadIdentity()
        if identity == nil {
            let words = phrase ?? Mnemonic.generate()
            identity = try ConvoIdentity(words: words)
            try? words.joined(separator: " ").write(toFile: options.stateDirectory + "/phrase", atomically: true, encoding: .utf8)
            chmod(options.stateDirectory + "/phrase", 0o600)
        }
        let name = options.name ?? store.name ?? "convo-" + identity!.publicKey.hex.prefix(6)
        let directory: NodeDirectory
        if let directoryFactory { directory = await directoryFactory() }
        else {
            directory = NodeDirectory()
            var urls = options.nodes
            for u in store.nodeURLs where !urls.contains(u) { urls.append(u) }
            for u in urls { _ = try? await directory.add(url: u) }
            await directory.discover()
            store.nodeURLs = urls
        }
        let client = ConvoClient(identity: identity!, name: name, store: store, directory: directory)
        if options.minHosts != nil || options.maxHosts != nil {
            await client.setBounds(minTotal: options.minHosts, maxTotal: options.maxHosts)
        }
        await client.load()
        return client
    }

    /// Runs one command; returns the lines to print.
    public func run(_ words: [String]) async throws -> [String] {
        guard let command = words.first else { throw Failure.usage(Self.usage) }
        let args = Array(words.dropFirst())
        func group(_ hex: String) throws -> Hash32 {
            guard let h = Hash32(hex: hex) else { throw Failure.badArgument(hex) }
            return h
        }
        if command == "identity" {
            var phrase: [String]?
            var fresh: ConvoIdentity?
            var i = 0
            while i < args.count {
                switch args[i] {
                case "--new": phrase = Mnemonic.generate()
                case "--phrase": i += 1; guard i < args.count else { throw Failure.usage("--phrase WORDS") }; phrase = args[i].split(separator: " ").map(String.init)
                case "--secret":
                    i += 1; guard i < args.count else { throw Failure.usage("--secret KEY") }
                    let raw = args[i]
                    guard let bytes = [UInt8](hex: raw), bytes.count == 64 || bytes.count == 32 else { throw Failure.badArgument("secret key") }
                    fresh = try ConvoIdentity(secretKey: bytes)
                default: throw Failure.usage("identity [--new | --phrase WORDS | --secret KEY]")
                }
                i += 1
            }
            if phrase != nil || fresh != nil { try? FileManager.default.removeItem(atPath: options.stateDirectory + "/identity.key") }
            let c = try await client(newIdentity: fresh, phrase: phrase)
            var lines = ["identity \(c.identity.publicKey.hex)", "name \(c.name)"]
            if let saved = try? String(contentsOfFile: options.stateDirectory + "/phrase", encoding: .utf8), phrase != nil { lines.append("recovery phrase: \(saved)") }
            return lines
        }
        let c = try await client()
        switch command {
        case "publish":
            let record = try await c.publishIdentity()
            try await c.publishKeyPackage()
            return ["published to \(record.nodes.map { $0.nodePk.hex.prefix(8) }.joined(separator: " "))"]
        case "nodes":
            var lines: [String] = []
            for n in await c.directory.known {
                let info = await c.directory.info(n)
                lines.append("\(n.hex) \(await c.health.isHealthy(n) ? "healthy" : "unhealthy") turn=\(info?.turn ?? false) batch=\(info?.batchSeq.map(String.init) ?? "-") \(await c.directory.url(n) ?? "")")
            }
            return lines.isEmpty ? ["no nodes; pass --node URL"] : lines
        case "create":
            var ids: [Hash32] = []
            var given: Hash32?
            var i = 0
            while i < args.count {
                if args[i] == "--salt", i + 1 < args.count { given = try group(args[i + 1]); i += 2 } else { ids.append(try group(args[i])); i += 1 }
            }
            let salt = try await c.beginCreation(members: ids, salt: given)
            return ["salt \(salt.hex)", "invited \(ids.count) identit\(ids.count == 1 ? "y" : "ies"); run: convo complete \(salt.hex)"]
        case "complete":
            guard args.count == 1 else { throw Failure.usage("complete SALT") }
            if let s = try await c.completeCreation(try group(args[0])) {
                try await c.submitLateCarries(try group(args[0]))
                return ["group \(s.groupID.hex)", "members \(s.genesis.members.count) quorum \(s.genesis.quorum) hosts \(s.genesis.homeNodes.count)"]
            }
            let state = await c.creationState(try group(args[0]))
            return ["waiting for announces (\(state?.complete == true ? "complete" : "incomplete"))"]
        case "join":
            guard args.count == 1 else { throw Failure.usage("join SALT") }
            if let s = try await c.join(salt: try group(args[0])) { return ["group \(s.groupID.hex)", "member_idx \(s.memberIdx)"] }
            return ["announced; run join again once the creator has sent the genesis"]
        case "groups":
            var lines: [String] = []
            for (id, s) in await c.groups.sorted(by: { $0.key < $1.key }) {
                lines.append("\(id.hex) members=\(s.genesis.members.count) idx=\(s.memberIdx) messages=\(await s.entries().count) committed=\(await s.commitments.count)")
            }
            return lines.isEmpty ? ["no groups"] : lines
        case "send":
            guard args.count >= 2 else { throw Failure.usage("send GROUP TEXT") }
            let signed = try await c.send(args.dropFirst().joined(separator: " "), in: try group(args[0]))
            return ["sent \(signed.hash.hex)"]
        case "pull":
            guard args.count == 1 else { throw Failure.usage("pull GROUP") }
            let n = try await c.pull(try group(args[0]))
            return ["pulled \(n) new"]
        case "show":
            guard args.count == 1 else { throw Failure.usage("show GROUP") }
            return try await Self.render(try await c.session(try group(args[0])))
        case "attest":
            guard args.count == 1 else { throw Failure.usage("attest GROUP") }
            let g = try group(args[0])
            guard let a = try await c.attest(g) else { return ["nothing new to attest"] }
            return ["attested \(a.attestation.head.hex) (\(a.attestation.msgCount) messages, root \(a.attestation.contentRoot.hex.prefix(16)))"]
        case "commitments":
            guard args.count == 1 else { throw Failure.usage("commitments GROUP") }
            let g = try group(args[0])
            let n = try await c.syncCommitments(g)
            let s = try await c.session(g)
            var lines = ["resolved \(n) new; \(await s.commitments.count) committed, \(await s.awaitingCommitment().count) awaiting"]
            for (item, ref) in await s.commitments.sorted(by: { $0.key < $1.key }) {
                lines.append("\(item.hex.prefix(16)) committed by \(ref.nodePk.hex.prefix(8)) batch \(ref.batchSeq) at \(ref.time) ms, \(ref.checkpoint.witnesses.count) witnesses")
            }
            return lines
        case "checkpoint":
            guard args.count == 1 else { throw Failure.usage("checkpoint NODE_PK") }
            let pk = try group(args[0])
            guard let w = await c.checkpoint(of: pk) else { return ["no checkpoint known for \(args[0])"] }
            let cp = w.checkpoint
            return ["seq \(cp.seq) root \(cp.root.hex) time \(cp.time) peaks \(cp.mmrPeaks.count) witnesses \(w.witnesses.count)\(w.isPublished() ? " (published)" : "")"]
        case "fork":
            guard args.count >= 1 else { throw Failure.usage("fork GROUP [--reason R] [--at HEAD] [ID...]") }
            var reason: Genesis.Reason = .membership
            var ids: [PublicKey] = []
            var at: Hash32?
            var i = 1
            while i < args.count {
                switch args[i] {
                case "--reason":
                    i += 1
                    switch args.count > i ? args[i] : "" {
                    case "membership": reason = .membership
                    case "recovery": reason = .recovery
                    case "rotation": reason = .keyRotation
                    case "host": reason = .hostChange
                    default: throw Failure.badArgument("reason")
                    }
                case "--at": i += 1; at = try group(args.count > i ? args[i] : "")
                default: ids.append(try group(args[i]))
                }
                i += 1
            }
            let salt = try await c.beginFork(try group(args[0]), members: ids.isEmpty ? nil : ids, reason: reason, forkHead: at)
            return ["salt \(salt.hex)", "run: convo complete \(salt.hex) (members: convo join \(salt.hex))"]
        case "republish":
            guard args.count == 2 else { throw Failure.usage("republish PARENT CHILD") }
            let n = try await c.republish(from: try group(args[0]), into: try group(args[1]))
            return ["republished \(n) message(s)"]
        case "rebase":
            guard args.count == 2 else { throw Failure.usage("rebase PARENT CHILD") }
            let n = try await c.rebase(from: try group(args[0]), into: try group(args[1]))
            return ["re-sent \(n) message(s)"]
        case "probe":
            guard args.count == 3 else { throw Failure.usage("probe GROUP ITEM NODE") }
            let status = try await c.probe(try group(args[1]), in: try group(args[0]), node: try group(args[2]))
            return ["\(status)"]
        case "fraud":
            let proofs = await c.fraudProofs
            return proofs.isEmpty ? ["no fraud proofs"] : proofs.map { "F\($0.tag) against \($0.nodePk.hex)" }
        case "hosts":
            guard args.count == 1 else { throw Failure.usage("hosts GROUP") }
            let g = try group(args[0])
            let s = try await c.session(g)
            var lines: [String] = []
            for h in await s.hosts { lines.append("\(h.hex) \(await c.health.isHealthy(h) ? "healthy" : "unhealthy")") }
            lines.append("host change due: \(await c.hostChangeDue(g))")
            return lines
        default:
            throw Failure.usage(Self.usage)
        }
    }

    /// §9.4 display: the canonical line, republished ranges indented and
    /// labeled, every entry with its state.
    public static func render(_ s: GroupSession) async -> [String] {
        let names = s.roster.map(\.body.name)
        var lines: [String] = []
        for e in await s.entries() {
            let who = Int(e.authorIdx) < names.count ? names[Int(e.authorIdx)] : "#\(e.authorIdx)"
            let state = e.state.rawValue.padding(toLength: 9, withPad: " ", startingAt: 0)
            if let rp = e.republished {
                let original = Int(rp.original) < names.count ? names[Int(rp.original)] : "#\(rp.original)"
                let verdict = rp.verified.map { $0 ? "verified" : "unverified" } ?? "unjudged"
                lines.append("\(state)   \(original): \(e.text ?? "")  [republished by \(who), \(verdict)]")
            } else if e.kind == .chat {
                lines.append("\(state) \(who): \(e.text ?? "(sealed)")")
            }
        }
        return lines.isEmpty ? ["(no messages)"] : lines
    }
}
