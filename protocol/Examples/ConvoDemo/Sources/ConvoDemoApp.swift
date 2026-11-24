import ConvoCalling
import ConvoClient
import ConvoCore
import ConvoNet
import ConvoWebRTC
import Communication
import CommunicationWebRTC
import SwiftUI

// The reference demo: the protocol end to end with nothing but SwiftUI.
// Point it at a node, publish your identity, create a group with a peer's
// identity (or join by salt), chat, and call. One file on purpose; it
// shows the package's surface, not an app design.

@main
struct ConvoDemoApp: App {
    @State private var model = DemoModel()
    var body: some Scene {
        WindowGroup {
            DemoRoot().environment(model)
                #if os(macOS)
                .frame(minWidth: 720, minHeight: 480)
                #endif
        }
    }
}

@MainActor @Observable
final class DemoModel {
    var nodeURL = "http://127.0.0.1:8080"
    var status = "not connected"
    var identityHex = ""
    var groups: [GroupRow] = []
    var selected: Hash32?
    var entries: [GroupSession.Entry] = []
    var names: [String] = []
    var draft = ""
    var peerHex = ""
    var saltHex = ""
    var call: CallState = .none
    var localView: WebRTCVideoView?
    var remoteView: WebRTCVideoView?

    struct GroupRow: Identifiable { let id: Hash32; let title: String }
    enum CallState: Equatable { case none, calling, ringing(video: Bool), active }

    private var client: ConvoClient?
    private var channel: PeerChannel?
    private var session: CallSession?
    private var listener: Task<Void, Never>?
    private var puller: Task<Void, Never>?

    func connect() async {
        do {
            let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                .appendingPathComponent("ConvoDemo").path
            let store = ClientStore(directory: dir)
            let identity = store.loadIdentity() ?? ConvoIdentity.random()
            let directory = NodeDirectory()
            _ = try await directory.add(url: nodeURL)
            let c = ConvoClient(identity: identity, name: store.name ?? "demo-" + String(identity.publicKey.hex.prefix(6)), store: store, directory: directory)
            await c.load()
            try await c.publishKeyPackage()
            client = c
            identityHex = identity.publicKey.hex
            status = "connected to \(nodeURL); KeyPackage published"
            await refreshGroups()
            puller?.cancel()
            puller = Task { [weak self] in
                while !Task.isCancelled {
                    await self?.pull()
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
        } catch { status = "connect failed: \(error)" }
    }

    func refreshGroups() async {
        guard let client else { return }
        var rows: [GroupRow] = []
        for (id, s) in await client.groups.sorted(by: { $0.key < $1.key }) {
            rows.append(GroupRow(id: id, title: s.roster.map(\.body.name).joined(separator: ", ")))
        }
        groups = rows
        if selected == nil { selected = rows.first?.id }
        await refreshEntries()
    }

    func refreshEntries() async {
        guard let client, let selected, let s = try? await client.session(selected) else { entries = []; return }
        entries = await s.entries()
        names = s.roster.map(\.body.name)
    }

    /// Creates a two-member group with the peer; the peer must `join` the
    /// printed salt. Both sides poll until the handshake completes.
    func create() async {
        guard let client, let peer = Hash32(hex: peerHex) else { status = "peer identity must be 64 hex characters"; return }
        do {
            let salt = try await client.beginCreation(members: [peer], homeNodes: await client.directory.known)
            saltHex = salt.hex
            status = "invited; the peer runs Join with salt \(salt.hex.prefix(12))…"
            for _ in 0..<60 {
                if let s = try await client.completeCreation(salt) { status = "group \(s.groupID.hex.prefix(12))… created"; break }
                try await Task.sleep(nanoseconds: 1_000_000_000)
            }
            await refreshGroups()
        } catch { status = "create failed: \(error)" }
    }

    func join() async {
        guard let client, let salt = Hash32(hex: saltHex) else { status = "salt must be 64 hex characters"; return }
        do {
            for _ in 0..<60 {
                if let s = try await client.join(salt: salt) { status = "joined \(s.groupID.hex.prefix(12))…"; break }
                try await Task.sleep(nanoseconds: 1_000_000_000)
            }
            await refreshGroups()
        } catch { status = "join failed: \(error)" }
    }

    func send() async {
        guard let client, let selected, !draft.isEmpty else { return }
        do { try await client.send(draft, in: selected); draft = "" } catch { status = "send failed: \(error)" }
        await refreshEntries()
    }

    func pull() async {
        guard let client else { return }
        for row in groups { _ = try? await client.pull(row.id); _ = try? await client.syncCommitments(row.id) }
        await refreshEntries()
        if channel == nil, call == .none { await listenForCall() }
    }

    // MARK: calls (Part III §22, §23, §25)

    private func peerAndNode() async -> (peer: PublicKey, node: NodeClient, group: GroupSession)? {
        guard let client, let selected, let s = try? await client.session(selected) else { return nil }
        let identities = await s.identities
        guard let peer = identities.first(where: { $0 != client.identity.publicKey }),
              let nodePk = await client.directory.known.first, let node = await client.directory.client(nodePk) else { return nil }
        return (peer, node, s)
    }

    /// Opens the data channel to the peer (caller side) and starts the call.
    func startCall(video: Bool) async {
        guard let client, let (peer, node, s) = await peerAndNode() else { status = "select a two-member group"; return }
        call = .calling
        do {
            if channel == nil {
                let signaling = RendezvousSignaling(node: node, groupID: s.groupID, me: client.identity.publicKey, peer: peer)
                channel = try await signaling.call(with: WebRTCConnector())
                startListening()
            }
            let session = try makeSession()
            let sdp = try await session.start(video: video)
            try await channel?.send(CallFrame.offer(sdp: sdp, video: video).wire)
            status = video ? "video calling…" : "calling…"
        } catch { status = "call failed: \(error)"; call = .none }
    }

    /// Callee side: waits for the peer's offer through the node, once.
    private func listenForCall() async {
        guard let client, let (peer, node, s) = await peerAndNode() else { return }
        var signaling = RendezvousSignaling(node: node, groupID: s.groupID, me: client.identity.publicKey, peer: peer)
        signaling.timeout = 1.5
        if let frames = try? await signaling.receive(), frames.contains(where: { if case .offer = $0 { return true } else { return false } }) {
            for f in frames { try? await signaling.send(f) }   // put them back; answer() reads its inbox
            if let ch = try? await signaling.answer(with: WebRTCConnector()) { channel = ch; startListening() }
        }
    }

    private func startListening() {
        guard let channel else { return }
        listener?.cancel()
        listener = Task { [weak self] in
            for await bytes in channel.incoming {
                guard let frame = try? CallFrame.fromWire(bytes) else { continue }
                await self?.handle(frame)
            }
            await self?.channelClosed()
        }
    }

    private var pendingOffer: (sdp: String, video: Bool)?

    private func handle(_ frame: CallFrame) async {
        switch frame {
        case .offer(let sdp, let video):
            pendingOffer = (sdp, video)
            call = .ringing(video: video)
            status = video ? "incoming video call" : "incoming call"
        case .answer(let sdp):
            try? await session?.accept(answer: sdp)
            call = .active
            status = "in call"
        case .end:
            await session?.end()
            session = nil
            call = .none
            status = "call ended"
        }
    }

    func accept() async {
        guard let offer = pendingOffer else { return }
        do {
            let session = try makeSession()
            let sdp = try await session.answer(offer: offer.sdp, video: offer.video)
            try await channel?.send(CallFrame.answer(sdp: sdp).wire)
            call = .active
            status = "in call"
        } catch { status = "answer failed: \(error)"; call = .none }
    }

    func hangUp() async {
        try? await channel?.send(CallFrame.end.wire)
        await session?.end()
        session = nil
        call = .none
        status = "call ended"
    }

    private func makeSession() throws -> CallSession {
        guard let channel else { throw NodeClient.Failure.badResponse }
        let s = CallSession(connection: channel.connection, devices: try WebRTCConnector().makeMediaDevices())
        Task { await s.watch() }
        session = s
        Task { @MainActor in
            localView = await s.makeLocalVideoView()
            remoteView = await s.makeRemoteVideoView()
        }
        return s
    }

    private func channelClosed() {
        channel = nil
        call = .none
    }
}

struct DemoRoot: View {
    @Environment(DemoModel.self) private var model
    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selected) {
                Section("Node") {
                    TextField("http://host:8080", text: $model.nodeURL)
                    Button("Connect and publish") { Task { await model.connect() } }
                    Text(model.identityHex.isEmpty ? "no identity yet" : model.identityHex).font(.caption.monospaced()).textSelection(.enabled)
                }
                Section("New group") {
                    TextField("peer identity (hex)", text: $model.peerHex)
                    Button("Create") { Task { await model.create() } }
                    TextField("salt (hex)", text: $model.saltHex)
                    Button("Join") { Task { await model.join() } }
                }
                Section("Groups") {
                    ForEach(model.groups) { row in Text(row.title.isEmpty ? row.id.hex : row.title).tag(row.id) }
                }
            }
            .onChange(of: model.selected) { Task { await model.refreshEntries() } }
        } detail: {
            VStack(spacing: 0) {
                if model.call == .active || model.call == .calling {
                    CallView()
                }
                List(model.entries, id: \.hash) { e in
                    HStack(alignment: .top) {
                        Text(Int(e.authorIdx) < model.names.count ? model.names[Int(e.authorIdx)] : "#\(e.authorIdx)").bold()
                        Text(e.text ?? "(unreadable)")
                        Spacer()
                        Text("\(e.state)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                if case .ringing(let video) = model.call {
                    HStack {
                        Text(video ? "Incoming video call" : "Incoming call")
                        Button("Accept") { Task { await model.accept() } }
                        Button("Decline") { Task { await model.hangUp() } }
                    }.padding()
                }
                HStack {
                    TextField("Message", text: $model.draft).onSubmit { Task { await model.send() } }
                    Button("Send") { Task { await model.send() } }
                    if model.call == .none {
                        Button("Call") { Task { await model.startCall(video: false) } }
                        Button("Video") { Task { await model.startCall(video: true) } }
                    } else {
                        Button("End") { Task { await model.hangUp() } }.tint(.red)
                    }
                }.padding()
                Text(model.status).font(.caption).foregroundStyle(.secondary).padding(.bottom, 6)
            }
        }
    }
}

struct CallView: View {
    @Environment(DemoModel.self) private var model
    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            if let remote = model.remoteView { VideoSurface(view: remote) } else { Color.black }
            if let local = model.localView {
                VideoSurface(view: local).frame(width: 120, height: 160).clipShape(RoundedRectangle(cornerRadius: 12)).padding(12)
            }
        }
        .frame(height: 240)
        .background(Color.black)
    }
}

#if canImport(UIKit)
struct VideoSurface: UIViewRepresentable {
    let view: WebRTCVideoView
    func makeUIView(context: Context) -> WebRTCVideoView { view }
    func updateUIView(_ uiView: WebRTCVideoView, context: Context) {}
}
#else
struct VideoSurface: NSViewRepresentable {
    let view: WebRTCVideoView
    func makeNSView(context: Context) -> WebRTCVideoView { view }
    func updateNSView(_ nsView: WebRTCVideoView, context: Context) {}
}
#endif
