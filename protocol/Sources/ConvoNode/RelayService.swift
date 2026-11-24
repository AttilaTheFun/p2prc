import Foundation

/// The relay a server runs beside its mailbox: a TURN server plus the
/// credential minter the mailbox's `/turn` endpoint uses. One object, so the
/// secret the relay verifies against and the one the mailbox mints from are
/// the same by construction.
///
/// What address to advertise and which ports were mapped is the caller's
/// business (a NAT'd phone maps a few ports; a cloud VM has them all).
public final class RelayService: @unchecked Sendable {
    public let server: TURNServer
    public let credentials: TURNCredentials
    /// The URLs clients hand their ICE agent, both transports: UDP first,
    /// TCP for networks that eat UDP.
    public let urls: [String]
    public let advertisedHost: String
    public let port: UInt16

    public init(listenPort: UInt16, advertisedHost: String, relayPorts: ClosedRange<UInt16>,
                credentials: TURNCredentials = TURNCredentials(secret: TURNCredentials.randomSecret())) {
        self.credentials = credentials
        self.port = listenPort
        self.advertisedHost = advertisedHost
        var configuration = TURNServer.Configuration(
            listenPort: listenPort, relayHost: advertisedHost, relayPorts: relayPorts, credentials: credentials
        )
        configuration.software = "p2prc-turn"
        server = TURNServer(configuration: configuration)
        let hostPort = advertisedHost.contains(":") ? "[\(advertisedHost)]:\(listenPort)" : "\(advertisedHost):\(listenPort)"
        urls = ["turn:\(hostPort)?transport=udp", "turn:\(hostPort)?transport=tcp"]
    }

    public func start() throws { try server.start() }
    public func stop() { server.stop() }

}
