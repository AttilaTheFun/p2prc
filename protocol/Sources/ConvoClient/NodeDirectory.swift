import ConvoCore
import ConvoSession
import ConvoNet
import Foundation

/// Node keys to node clients (§24). There is no registry: the client
/// learns nodes from its defaults, identity records and invitations, and
/// each node's `/servers` list, and confirms each by its descriptor at
/// `/v1/node`.
public actor NodeDirectory {
    public typealias TransportFactory = @Sendable (URL) -> any NodeTransport

    private var clients: [PublicKey: NodeClient] = [:]
    private var urls: [PublicKey: String] = [:]
    private var infos: [PublicKey: NodeInfo] = [:]
    private let factory: TransportFactory

    public init(factory: @escaping TransportFactory = { HTTPNodeTransport(base: $0) }) { self.factory = factory }

    /// Registers a node reached through `transport` (tests pass an
    /// in-process one). Returns its key.
    @discardableResult
    public func add(transport: any NodeTransport, url: String? = nil) async throws -> PublicKey {
        let client = NodeClient(transport: transport)
        let info = try await client.info()
        guard let pk = info.publicKey else { throw NodeClient.Failure.badResponse }
        clients[pk] = client
        infos[pk] = info
        if let url { urls[pk] = url }
        return pk
    }

    @discardableResult
    public func add(url: String) async throws -> PublicKey {
        guard let u = URL(string: url) else { throw NodeClient.Failure.badResponse }
        return try await add(transport: factory(u), url: url)
    }

    /// Follows `/servers` from every known node once, adding what it finds.
    public func discover() async {
        for (_, client) in clients {
            guard let data = try? await client.get("/servers"),
                  let list = try? JSONDecoder().decode(ServerList.self, from: Data(data)) else { continue }
            for entry in list.servers where !urls.values.contains(entry.url) {
                _ = try? await add(url: entry.url)
            }
        }
    }

    public func client(_ node: PublicKey) -> NodeClient? { clients[node] }

    public func info(_ node: PublicKey) -> NodeInfo? { infos[node] }
    public func url(_ node: PublicKey) -> String? { urls[node] }
    public var known: [PublicKey] { clients.keys.sorted() }
}
