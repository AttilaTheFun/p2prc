import Communication
import CommunicationWebRTC
import ConvoCalling
import Foundation

/// WebRTC for the native clients.
///
/// The browser gets `RTCPeerConnection` from the platform; iOS and macOS get
/// it from the Communication package. Both ends of this are mechanical and
/// deliberately mirror the JS host: make an offer, take an offer, apply an
/// answer, send a frame. The guest cannot tell which one it is talking to,
/// which is the point — the same client code drives pairing on every client.
///
/// One connection per peer id, all held here: the guest scopes every call by
/// an opaque id, so several conversations can be live at once. Reusing an id
/// replaces its connection, which is exactly what a reconnect wants.
///
actor NativeWebRTC {
    /// The label both sides agree on. The browser opens "convo"; so do we.
    private static let channelLabel = "convo"

    private let connector: any CommunicationConnector = WebRTCConnector()
    private var connections: [String: any CommunicationPeerConnection] = [:]
    private var events: [String: Task<Void, Never>] = [:]
    /// The call on each peer's connection (ConvoCalling, spec §25), made on
    /// the first call and dropped with the connection.
    private var media: [String: CallSession] = [:]

    /// Fires when a data channel opens and when frames arrive, matching the
    /// events the JS host emits. Every callback names the peer it is about.
    private let onOpen: @Sendable (String) -> Void
    private let onFrame: @Sendable (String, String) -> Void
    private let onState: @Sendable (String, String) -> Void

    init(
        onOpen: @escaping @Sendable (String) -> Void,
        onFrame: @escaping @Sendable (String, String) -> Void,
        onState: @escaping @Sendable (String, String) -> Void
    ) {
        self.onOpen = onOpen
        self.onFrame = onFrame
        self.onState = onState
    }

    /// Set by the host from the guest's directory-driven list; peers first,
    /// Google last.
    private var iceServers: [CommunicationICEServer] = [.stun("stun:stun.l.google.com:19302")]

    func setIceServers(_ servers: [CommunicationICEServer]) {
        iceServers = servers
    }

    private func makeConnection(for peer: String) throws -> any CommunicationPeerConnection {
        close(peer: peer)
        // CONVO_DEBUG_RELAY=1: relay candidates only, so a test on one
        // machine exercises the TURN path a phone on another network needs.
        let relayOnly = ProcessInfo.processInfo.environment["CONVO_DEBUG_RELAY"] == "1"
        let configuration = CommunicationConfiguration(iceServers: iceServers, iceTransportPolicy: relayOnly ? .relay : .all)
        let connection = try connector.makePeerConnection(configuration: configuration)
        connections[peer] = connection
        observe(connection, peer: peer)
        return connection
    }

    func close(peer: String) {
        events[peer]?.cancel()
        events[peer] = nil
        if let session = media.removeValue(forKey: peer) { Task { await session.end() } }
        // The connection is its own actor; let the teardown land on it
        // without holding this one up.
        if let connection = connections.removeValue(forKey: peer) {
            Task { await connection.close() }
        }
    }

    private func observe(_ connection: any CommunicationPeerConnection, peer: String) {
        events[peer] = Task { [onOpen, onFrame, onState] in
            for await event in connection.events {
                switch event {
                case .dataChannelOpened:
                    onOpen(peer)
                case let .dataChannelMessage(_, message):
                    if case let .binary(data) = message { onFrame(peer, data.base64EncodedString()) }
                case let .connectionStateChanged(state):
                    onState(peer, "\(state)")
                default:
                    break
                }
            }
        }
    }

    /// Creates an offer with the data channel already in it, gathers ICE, and
    /// returns the packed blob.
    ///
    /// ICE is gathered fully before returning rather than trickled: the blob
    /// has to be self-contained because it travels as a link or a QR code,
    /// with no channel to send later candidates over.
    func createOffer(peer: String) async throws -> String {
        let connection = try makeConnection(for: peer)
        try await connection.openDataChannel(label: Self.channelLabel)
        let offer = try await connection.offer()
        try await connection.setLocalDescription(offer)
        let gathered = try await waitForGathering(connection, fallback: offer)
        return gathered.sdp
    }

    /// Takes a peer's offer and returns our packed answer.
    func acceptOffer(peer: String, blob: String) async throws -> String {
        let connection = try makeConnection(for: peer)
        try await connection.setRemoteDescription(
            CommunicationSessionDescription(kind: .offer, sdp: blob)
        )
        let answer = try await connection.answer()
        try await connection.setLocalDescription(answer)
        let gathered = try await waitForGathering(connection, fallback: answer)
        return gathered.sdp
    }

    /// Applies the answer to the offer we are holding open.
    func acceptAnswer(peer: String, blob: String) async throws {
        guard let connection = connections[peer] else { return }
        try await connection.setRemoteDescription(
            CommunicationSessionDescription(kind: .answer, sdp: blob)
        )
    }

    func send(peer: String, bytes: Data) async {
        try? await connections[peer]?.send(data: bytes, on: Self.channelLabel)
    }

    // MARK: - Calls
    //
    // Audio is added to the live connection, so the renegotiation offer/answer
    // carries the new audio m-line alongside the existing data channel. The
    // SDP travels the authenticated channel as a call frame, exactly as in the
    // browser — the two clients renegotiate the same way.

    /// Adds the microphone (and the camera, for video) and returns a
    /// renegotiation offer.
    func callStart(peer: String, video: Bool) async throws -> String {
        guard let session = try callMedia(peer: peer) else { throw Failure.noConnection }
        let sdp = try await session.start(video: video)   // §25.1: tracks on, offer gathered
        Self.logMedia("call offer", sdp)
        return sdp
    }

    /// The media lines and their directions, for the log: what each side
    /// agreed to send and receive.
    private static func logMedia(_ label: String, _ sdp: String) {
        let lines = sdp.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
        let summary = lines.filter {
            $0.hasPrefix("m=") || $0 == "a=sendrecv" || $0 == "a=sendonly" || $0 == "a=recvonly" || $0 == "a=inactive"
        }
        NSLog("Convo %@ media (%d lines): %@", label, lines.count, summary.joined(separator: " | "))
    }

    /// Applies the peer's call SDP. For an offer, adds our own microphone
    /// (and camera, for video) and returns an answer; for an answer,
    /// returns "".
    func callApplyRemote(peer: String, sdp: String, isOffer: Bool, video: Bool) async throws -> String {
        guard let session = try callMedia(peer: peer) else { throw Failure.noConnection }
        Self.logMedia(isOffer ? "remote offer" : "remote answer", sdp)
        guard isOffer else { try await session.accept(answer: sdp); return "" }
        let answer = try await session.answer(offer: sdp, video: video)   // §25.2–25.3
        Self.logMedia("call answer", answer)
        return answer
    }

    /// Ends the call: drop the microphone. The connection and chat survive;
    /// the removed m-line is settled on the next renegotiation, and the peer's
    /// callEnd frame prompts the symmetric removal on their side.
    func callEnd(peer: String) async {
        await media[peer]?.end()
        media[peer] = nil
    }

    /// The peer's call session, made on first use over the connection; it
    /// hands out the video views.
    func callMedia(peer: String) throws -> CallSession? {
        if let existing = media[peer] { return existing }
        guard let connection = connections[peer] else { return nil }
        let fresh = CallSession(connection: connection, devices: try connector.makeMediaDevices())
        Task { await fresh.watch() }
        media[peer] = fresh
        return fresh
    }

    enum Failure: Error { case noConnection }

    /// Waits for ICE to finish, capped so a candidate that never arrives
    /// cannot hang pairing. The local description is re-read afterwards
    /// because gathering is what fills in the candidates.
    private func waitForGathering(
        _ connection: any CommunicationPeerConnection,
        fallback: CommunicationSessionDescription
    ) async throws -> CommunicationSessionDescription {
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            if case .complete = await connection.iceGatheringState { break }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return await connection.localDescription ?? fallback
    }
}
