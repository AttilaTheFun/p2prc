import Communication
import CommunicationWebRTC
import ConvoCore
import ConvoNet
import Foundation

/// Part III §25 on Apple platforms: a call on an existing peer connection.
/// The caller adds the microphone (and camera) and offers; the callee puts
/// its own tracks on the offer's transceivers and answers; either side ends
/// by removing its tracks, after which the next negotiation settles the
/// lines. Video views render the local and the remote camera, whichever
/// track is attached now or later.
public actor CallSession {
    public enum State: Sendable, Equatable { case idle, offering, ringing, active, ended }

    public let connection: any CommunicationPeerConnection
    private let devices: any CommunicationMediaDevices
    public private(set) var state: State = .idle
    public private(set) var video = false
    private var audioTrack: WebRTCMediaTrack?
    private var videoTrack: WebRTCMediaTrack?
    private var audioSender: (any CommunicationRtpSender)?
    private var videoSender: (any CommunicationRtpSender)?
    private var localViews: [WebRTCVideoView] = []
    private var remoteViews: [WebRTCVideoView] = []
    private var remoteVideoTracks: [String: WebRTCMediaTrack] = [:]
    private var attached: Set<String> = []
    private var watcher: Task<Void, Never>?

    public init(connection: any CommunicationPeerConnection, devices: any CommunicationMediaDevices) {
        self.connection = connection
        self.devices = devices
    }

    /// Follows the connection's track events so remote video attaches as
    /// it arrives. Call once.
    public func watch() {
        guard watcher == nil else { return }
        let events = connection.events
        watcher = Task { [weak self] in
            for await event in events {
                if case .trackAdded(let kind, _) = event, kind == .video { await self?.attachRemote() }
            }
        }
    }

    // MARK: §25.1 caller

    /// Adds the microphone (and the camera) and returns the offer to send
    /// as `CallFrame.offer`.
    public func start(video: Bool) async throws -> String {
        self.video = video
        try await addLocalMedia(video: video)
        let offer = try await connection.offer(options: CommunicationOfferOptions(receivesAudio: true, receivesVideo: video))
        try await connection.setLocalDescription(offer)
        state = .offering
        return try await gathered(offer).sdp
    }

    /// The callee's answer arrived.
    public func accept(answer sdp: String) async throws {
        try await connection.setRemoteDescription(CommunicationSessionDescription(kind: .answer, sdp: sdp))
        state = .active
        attachRemote()
    }

    // MARK: §25.2 callee

    /// An offer arrived: nothing is added yet; the app decides.
    public func ring(video: Bool) { self.video = video; state = .ringing }

    /// Applies the offer, adds this side's media on the offer's
    /// transceivers (§25.3), and returns the answer to send as
    /// `CallFrame.answer`.
    public func answer(offer sdp: String, video: Bool) async throws -> String {
        self.video = video
        try await connection.setRemoteDescription(CommunicationSessionDescription(kind: .offer, sdp: sdp))
        try await addLocalMedia(video: video)
        let answer = try await connection.answer(options: CommunicationAnswerOptions(receivesAudio: true, receivesVideo: video))
        try await connection.setLocalDescription(answer)
        state = .active
        attachRemote()
        return try await gathered(answer).sdp
    }

    // MARK: §25.4 end

    /// Removes this side's tracks. The peer's `end` frame (or ours) tells
    /// the other side to do the same; the next negotiation settles it.
    public func end() async {
        if let s = audioSender { try? await connection.removeTrack(s) }
        if let s = videoSender { try? await connection.removeTrack(s) }
        audioTrack?.stop(); videoTrack?.stop()
        for v in localViews { videoTrack?.remove(renderer: v) }
        audioSender = nil; videoSender = nil; audioTrack = nil; videoTrack = nil
        state = .ended
    }

    // MARK: controls

    public func setMuted(_ muted: Bool) { audioTrack?.isEnabled = !muted }
    public func setCameraEnabled(_ enabled: Bool) { videoTrack?.isEnabled = enabled }
    public var hasLocalVideo: Bool { videoTrack != nil }

    // MARK: views

    @MainActor
    public func makeLocalVideoView() async -> WebRTCVideoView {
        let view = WebRTCVideoView.make()
        await registerLocal(view)
        return view
    }

    @MainActor
    public func makeRemoteVideoView() async -> WebRTCVideoView {
        let view = WebRTCVideoView.make()
        await registerRemote(view)
        return view
    }

    private func registerLocal(_ view: WebRTCVideoView) {
        localViews.append(view)
        videoTrack?.add(renderer: view)
    }

    private func registerRemote(_ view: WebRTCVideoView) {
        remoteViews.append(view)
        attachRemote()
    }

    // MARK: internals

    /// §25.3: reuse a spare receive-only transceiver of the kind (the
    /// offer's), else add a track, so the answer carries our media on the
    /// offer's lines. A device that is missing (no camera on a headless
    /// Mac, no microphone) is skipped: the call still receives that kind,
    /// as a browser does when `getUserMedia` fails for one of them.
    private func addLocalMedia(video wantsVideo: Bool) async throws {
        if audioTrack == nil, let track = (try? devices.audioTrack()) as? WebRTCMediaTrack {
            audioTrack = track
            audioSender = try? await attach(track, kind: .audio)
        }
        if wantsVideo, videoTrack == nil, let track = (try? devices.videoTrack(camera: .front)) as? WebRTCMediaTrack {
            videoTrack = track
            videoSender = try? await attach(track, kind: .video)
            for v in localViews { track.add(renderer: v) }
        }
    }

    public var hasLocalAudio: Bool { audioTrack != nil }

    private func attach(_ track: WebRTCMediaTrack, kind: CommunicationMediaKind) async throws -> any CommunicationRtpSender {
        for t in await connection.transceivers where t.kind == kind && !t.isStopped && t.sender.track == nil
            && (t.direction == .recvOnly || t.direction == .inactive) {
            try await t.sender.replaceTrack(track)
            try t.setDirection(.sendRecv)
            return t.sender
        }
        return try await connection.addTrack(track, streamIDs: ["convo-call"])
    }

    /// Every remote video track, held so its renderers stay attached.
    private func attachRemote() {
        Task { [weak self] in
            guard let self else { return }
            let receivers = await self.connection.receivers
            await self.attachRemote(from: receivers)
        }
    }

    private func attachRemote(from receivers: [any CommunicationRtpReceiver]) {
        for receiver in receivers {
            guard let fresh = receiver.track as? WebRTCMediaTrack, fresh.kind == .video else { continue }
            let track = remoteVideoTracks[fresh.id] ?? fresh
            remoteVideoTracks[fresh.id] = track
            for view in remoteViews {
                let key = "\(track.id)-\(ObjectIdentifier(view).hashValue)"
                if attached.insert(key).inserted { track.add(renderer: view) }
            }
        }
    }

    /// Waits for ICE to finish (capped), then re-reads the description so
    /// the SDP carries the candidates: call frames travel once.
    private func gathered(_ fallback: CommunicationSessionDescription) async throws -> CommunicationSessionDescription {
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            if case .complete = await connection.iceGatheringState { break }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        return await connection.localDescription ?? fallback
    }
}
