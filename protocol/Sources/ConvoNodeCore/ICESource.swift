import ConvoNet
import ConvoFoundation

/// Where a node's `/ice` answers come from (§21): its own relay's
/// credentials, a TURN service's, or a host that answers `/ice` itself (a
/// Worker minting Cloudflare credentials).
public protocol ICESource: Sendable {
    /// Whether clients get TURN from this node, for `/health` and `/v1/node`.
    var offersTURN: Bool { get }
    var stunURLs: [String] { get }
    /// The servers for one client, and how long they last (seconds).
    func iceServers(for clientID: String, now: Date) -> (servers: [ICEServer], ttl: Int)
}

/// A fixed answer: what the host says it offers, with any servers it lists.
public struct StaticICE: ICESource {
    public var offersTURN: Bool
    public var stunURLs: [String]
    public var servers: [ICEServer]
    public var ttl: Int

    public init(offersTURN: Bool, stunURLs: [String] = [], servers: [ICEServer] = [], ttl: Int = 3600) {
        self.offersTURN = offersTURN; self.stunURLs = stunURLs; self.servers = servers; self.ttl = ttl
    }

    public func iceServers(for clientID: String, now: Date) -> (servers: [ICEServer], ttl: Int) { (servers, ttl) }
}
