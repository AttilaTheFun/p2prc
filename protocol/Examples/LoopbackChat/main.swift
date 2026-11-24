import ConvoClient
import ConvoCore
import ConvoNet
import ConvoNode
import Foundation

// A whole Convo network in one process: three nodes that witness one
// another's logs, two identities that pair through a node's rendezvous
// boxes, exchange messages, attest, and watch their home node commit
// their items in a checkpoint the other two cosign.

struct InProcess: NodeTransport {
    let node: ConvoNodeServer
    func request(_ method: String, _ path: String, body: [UInt8], contentType: String, headers: [String: String]) async throws -> (status: Int, body: [UInt8]) {
        let r = node.respond(to: HTTPRequest(method: method, path: path, body: Data(body), headers: headers, peer: "127.0.0.1:1"))
        return (r.status, Array(r.body))
    }
}

let nodes = (0..<3).map { i in
    ConvoNodeServer(configuration: .init(id: "loopback-\(i)"), key: SigningKey.random(), ice: ICEProvider(mode: .none), fetch: { _, _, _ in (0, nil) })
}
let home = nodes[0]
let committer = Committer(nodeKey: home.key, mailbox: home.mailbox)
await committer.setLog { print("node: \($0)") }
await committer.setWitnesses { nodes.dropFirst().map { ($0.configuration.id, NodeClient(transport: InProcess(node: $0))) } }

func client(_ name: String) async throws -> ConvoClient {
    let directory = NodeDirectory()
    for node in nodes { _ = try await directory.add(transport: InProcess(node: node)) }
    let c = ConvoClient(identity: .random(), name: name, directory: directory)
    await c.setBounds(minHealthy: 1, minTotal: 1, maxTotal: 1)
    try await c.publishKeyPackage()
    return c
}
let alice = try await client("alice"), bob = try await client("bob")
let salt = try await alice.beginCreation(members: [bob.identity.publicKey], homeNodes: [home.nodePk])
_ = try await bob.join(salt: salt)
let group = try await alice.completeCreation(salt)!
_ = try await bob.join(salt: salt)
print("group \(group.groupID.hex.prefix(16)) created; genesis held by the node: \(home.mailbox.genesis(groupID: group.groupID) != nil)")

try await alice.send("hello bob", in: group.groupID)
print("bob pulled \(try await bob.pull(group.groupID))")
try await bob.send("hi alice", in: group.groupID)
print("alice pulled \(try await alice.pull(group.groupID)); node holds \(home.mailbox.items(groupID: group.groupID).count) items")
_ = try await alice.attest(group.groupID)
try await bob.pull(group.groupID)
_ = try await bob.attest(group.groupID)

// The node commits everything it receipted and its witnesses cosign the
// checkpoint; the clients resolve the refs.
await committer.commit()
print("checkpoint published: \(home.mailbox.checkpoint?.isPublished() ?? false)")
try await alice.syncCommitments(group.groupID)
try await bob.syncCommitments(group.groupID)
for line in await render(try await alice.session(group.groupID)) { print(line) }

func render(_ s: GroupSession) async -> [String] {
    await s.entries().map { "\($0.state.rawValue.padding(toLength: 9, withPad: " ", startingAt: 0)) \(s.roster[Int($0.authorIdx)].body.name): \($0.text ?? "")" }
}
