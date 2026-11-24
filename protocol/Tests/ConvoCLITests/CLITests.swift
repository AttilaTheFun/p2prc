import ConvoClient
import ConvoCore
import ConvoNet
import ConvoNode
import Foundation
import Testing
@testable import ConvoCLI

/// The CLI against in-process nodes: every command a script would run,
/// in the order the protocol needs them.
struct CLIWorld {
    let nodeKeys: [SigningKey]
    let nodes: [ConvoNodeServer]
    let committers: [Committer]
    let dirs: [String]

    init() async throws {
        nodeKeys = (0..<3).map { i in try! SigningKey(seed: [UInt8](repeating: UInt8(0xb0 + i), count: 32)) }
        nodes = nodeKeys.enumerated().map { i, key in
            ConvoNodeServer(configuration: .init(id: "n\(i)"), key: key, ice: ICEProvider(mode: .none), fetch: { _, _, _ in (0, nil) })
        }
        var committers: [Committer] = []
        for (i, n) in nodes.enumerated() {
            let c = Committer(nodeKey: nodeKeys[i], mailbox: n.mailbox)
            let others = nodes.filter { $0.nodePk != n.nodePk }
            await c.setWitnesses { others.map { ($0.configuration.id, NodeClient(transport: InProcessTransport(node: $0))) } }
            committers.append(c)
        }
        self.committers = committers
        dirs = (0..<3).map { _ in NSTemporaryDirectory() + "convo-cli-\(UUID().uuidString)" }
    }

    func cleanup() { for d in dirs { try? FileManager.default.removeItem(atPath: d) } }

    func commitAll() async {
        for c in committers { await c.commit() }
    }

    func run(_ who: Int, _ words: String...) async throws -> [String] {
        var options = ConvoCLI.Options(stateDirectory: dirs[who])
        options.name = "m\(who)"
        let cli = ConvoCLI(options: options, directoryFactory: {
            let d = NodeDirectory()
            for n in nodes { _ = try? await d.add(transport: InProcessTransport(node: n)) }
            return d
        })
        return try await cli.run(words)
    }
}

struct InProcessTransport: NodeTransport {
    let node: ConvoNodeServer
    func request(_ method: String, _ path: String, body: [UInt8], contentType: String, headers: [String: String]) async throws -> (status: Int, body: [UInt8]) {
        let response = node.respond(to: HTTPRequest(method: method, path: path, body: Data(body), headers: headers, peer: "127.0.0.1:1"))
        return (response.status, Array(response.body))
    }
}

@Test func parseOptions() throws {
    let (o, rest) = try ConvoCLI.parse(["--state", "/tmp/x", "--node", "http://a", "--node", "http://b", "send", "g", "hi", "there"], environment: [:])
    #expect(o.stateDirectory == "/tmp/x" && o.nodes == ["http://a", "http://b"])
    #expect(rest == ["send", "g", "hi", "there"])
    let (e, _) = try ConvoCLI.parse([], environment: ["CONVO_NODES": "http://c,http://d", "CONVO_STATE": "/s"])
    #expect(e.nodes == ["http://c", "http://d"] && e.stateDirectory == "/s")
    #expect(throws: ConvoCLI.Failure.self) { try ConvoCLI.parse(["--help"], environment: [:]) }
}

@Test func endToEndThroughCommands() async throws {
    let w = try await CLIWorld()
    defer { w.cleanup() }
    var ids: [String] = []
    for i in 0..<3 {
        let lines = try await w.run(i, "identity", "--new")
        ids.append(String(lines[0].dropFirst("identity ".count)))
        #expect(lines.contains { $0.hasPrefix("recovery phrase: ") && $0.split(separator: " ").count == 14 })
        _ = try await w.run(i, "publish")
    }
    // The phrase restores the same identity.
    let phrase = try String(contentsOfFile: w.dirs[0] + "/phrase", encoding: .utf8)
    #expect(try await w.run(0, "identity", "--phrase", phrase)[0] == "identity \(ids[0])")

    let salt = String(try await w.run(0, "create", ids[1], ids[2])[0].dropFirst("salt ".count))
    _ = try await w.run(1, "join", salt)
    _ = try await w.run(2, "join", salt)
    let created = try await w.run(0, "complete", salt)
    #expect(created[0].hasPrefix("group "))
    let g = String(created[0].dropFirst("group ".count))
    #expect(try await w.run(1, "join", salt)[0] == "group \(g)")
    #expect(try await w.run(2, "join", salt)[0] == "group \(g)")
    #expect(try await w.run(1, "groups").count == 1)

    #expect(try await w.run(0, "send", g, "hello", "world")[0].hasPrefix("sent "))
    #expect(try await w.run(1, "pull", g) == ["pulled 1 new"])
    #expect(try await w.run(1, "show", g) == ["sent      m0: hello world"])
    let hiHash = String(try await w.run(1, "send", g, "hi")[0].dropFirst("sent ".count))
    #expect(try await w.run(0, "pull", g) == ["pulled 1 new"])
    #expect(try await w.run(0, "attest", g)[0].hasPrefix("attested "))
    _ = try await w.run(1, "pull", g)
    #expect(try await w.run(1, "attest", g)[0].hasPrefix("attested "))
    _ = try await w.run(0, "pull", g)
    #expect(try await w.run(0, "show", g) == ["attested  m0: hello world", "attested  m1: hi"])
    await w.commitAll()
    #expect(try await w.run(0, "commitments", g)[0].hasPrefix("resolved "))
    #expect(try await w.run(0, "show", g) == ["committed m0: hello world", "committed m1: hi"])
    _ = try await w.run(2, "pull", g)
    #expect(try await w.run(2, "commitments", g)[0].hasPrefix("resolved "))
    #expect(try await w.run(2, "show", g) == ["committed m0: hello world", "committed m1: hi"])
    #expect(try await w.run(0, "hosts", g).last == "host change due: false")
    #expect(try await w.run(0, "checkpoint", w.nodeKeys[0].publicKey.hex)[0].hasSuffix("witnesses 2 (published)"))

    // Past the fork point: one message committed under a committed attestation, one in flight.
    _ = try await w.run(0, "send", g, "after")
    _ = try await w.run(0, "attest", g)
    await w.commitAll()
    _ = try await w.run(0, "commitments", g)
    _ = try await w.run(0, "send", g, "in flight")
    let fsalt = String(try await w.run(0, "fork", g, "--reason", "membership", "--at", hiHash, ids[1])[0].dropFirst("salt ".count))
    _ = try await w.run(1, "join", fsalt)
    let child = String(try await w.run(0, "complete", fsalt)[0].dropFirst("group ".count))
    _ = try await w.run(1, "join", fsalt)
    _ = try await w.run(0, "complete", fsalt)   // collects member 1's carry signature
    #expect(w.nodes[0].mailbox.genesis(groupID: Hash32(hex: child)!)?.carrySigs.count == 2)
    #expect(try await w.run(0, "republish", g, child) == ["republished 1 message(s)"])
    #expect(try await w.run(0, "rebase", g, child) == ["re-sent 1 message(s)"])
    _ = try await w.run(1, "pull", child)
    let shown = try await w.run(1, "show", child)
    #expect(shown.count == 2)
    // The child cannot open the parent's ciphertext (§9.5); the entry is history, attributed and marked.
    #expect(shown.first?.contains("m0: [republished message") == true && shown.first?.contains("[republished by m0, verified]") == true)
    #expect(shown.last == "sent      m0: in flight")

    // Fraud: node 0 drops a committed item; probe builds F1, and the other nodes keep it.
    let sent = String(try await w.run(0, "send", child, "kept")[0].dropFirst("sent ".count))
    await w.commitAll()
    _ = w.nodes[0].mailbox.expire(now: UInt64.max)
    #expect(try await w.run(0, "probe", child, sent, w.nodes[0].nodePk.hex) == ["notFound"])
    #expect(w.nodes[1].mailbox.provenFaulty == [w.nodes[0].nodePk])
    #expect(try await w.run(0, "fraud")[0].hasPrefix("F1 against"))
}
