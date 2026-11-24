import Communication
import ConvoCore
import ConvoNet
import Foundation

/// Part III signaling: offer, answer and ICE candidates exchanged as
/// frames through a node's rendezvous boxes, addressed per (salt,
/// recipient) like the handshake. ICE servers come from the node's
/// `/ice`. Both members must reach the same node; the caller picks it
/// from the group's healthy hosts (the callee polls every host).
public struct RendezvousSignaling: Sendable {
    public typealias Frame = SignalingFrame

    public let node: NodeClient
    /// The conversation this channel serves; boxes are keyed by it.
    public let groupID: Hash32
    public let me: PublicKey
    public let peer: PublicKey
    public var pollInterval: TimeInterval = 0.5
    public var timeout: TimeInterval = 30

    public init(node: NodeClient, groupID: Hash32, me: PublicKey, peer: PublicKey) {
        self.node = node; self.groupID = groupID; self.me = me; self.peer = peer
    }

    /// Box names: `H("convo/hs" ‖ group_id ‖ recipient)`, the handshake's
    /// scheme with the group as the salt.
    var inbox: String { NodeAPI.handshakeBox(salt: groupID, recipient: me) }
    var outbox: String { NodeAPI.handshakeBox(salt: groupID, recipient: peer) }

    public func send(_ frame: Frame) async throws { try await node.drop(frame.wire, box: outbox) }

    public func receive() async throws -> [Frame] {
        var frames: [Frame] = []
        while let bytes = try await node.poll(box: inbox) { frames.append(try Frame.fromWire(bytes)) }
        return frames
    }

    /// The node's ICE servers as a Communication configuration.
    public func configuration() async throws -> CommunicationConfiguration {
        let answer = try await node.ice(for: me.hex)
        let servers = answer.iceServers.map { CommunicationICEServer(urls: $0.urls, username: $0.username, credential: $0.credential) }
        return CommunicationConfiguration(iceServers: servers)
    }

    /// Runs the caller's side: opens the channel, offers, relays
    /// candidates, waits for the answer. Returns once the channel is open.
    public func call(with connector: any CommunicationConnector) async throws -> PeerChannel {
        let connection = try connector.makePeerConnection(configuration: try await configuration())
        let channel = PeerChannel(connection: connection)
        let relay = relayCandidates(connection)
        try await channel.open()
        let offer = try await connection.offer(options: CommunicationOfferOptions())
        try await connection.setLocalDescription(offer)
        try await send(.offer(sdp: offer.sdp))
        try await drive(connection, expecting: .answer)
        await channel.ready()
        relay.cancel()
        return channel
    }

    /// Runs the callee's side: waits for the offer, answers, relays candidates.
    public func answer(with connector: any CommunicationConnector) async throws -> PeerChannel {
        let connection = try connector.makePeerConnection(configuration: try await configuration())
        let channel = PeerChannel(connection: connection)
        let relay = relayCandidates(connection)
        try await drive(connection, expecting: .offer)
        await channel.ready()
        relay.cancel()
        return channel
    }

    private func relayCandidates(_ connection: any CommunicationPeerConnection) -> Task<Void, Never> {
        let events = connection.events
        let signaling = self
        return Task {
            for await event in events {
                if case .localCandidateDiscovered(let c) = event { try? await signaling.send(.candidate(sdp: c.sdp, sdpMLineIndex: c.sdpMLineIndex, sdpMid: c.sdpMid)) }
            }
        }
    }

    /// Polls the inbox until the expected description has arrived and been
    /// applied, feeding candidates as they come.
    private func drive(_ connection: any CommunicationPeerConnection, expecting kind: CommunicationSessionDescription.Kind) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        var done = false
        while !done {
            for frame in try await receive() {
                switch frame {
                case .offer(let sdp) where kind == .offer:
                    try await connection.setRemoteDescription(CommunicationSessionDescription(kind: .offer, sdp: sdp))
                    let answer = try await connection.answer(options: CommunicationAnswerOptions())
                    try await connection.setLocalDescription(answer)
                    try await send(.answer(sdp: answer.sdp))
                    done = true
                case .answer(let sdp) where kind == .answer:
                    try await connection.setRemoteDescription(CommunicationSessionDescription(kind: .answer, sdp: sdp))
                    done = true
                case .candidate(let sdp, let index, let mid):
                    try? await connection.addRemoteCandidate(CommunicationICECandidate(sdp: sdp, sdpMLineIndex: index, sdpMid: mid))
                default: break
                }
            }
            if !done {
                guard Date() < deadline else { throw NodeClient.Failure.badResponse }
                try await Task.sleep(nanoseconds: UInt64(pollInterval * 1e9))
            }
        }
    }
}
