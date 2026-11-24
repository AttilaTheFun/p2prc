import Communication
import CommunicationWebRTC
import ConvoCalling
import ConvoApp
import SwiftUI
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif

/// Where a video call is shown: FaceTime's shape, not the chat's. On the
/// Mac a window of its own; on a phone a full-screen presentation. Drawn
/// by the app, not the shared UI: the views are the WebRTC backend's, and
/// the shared UI never takes a platform view from outside (the QR lesson).
///
/// Follows the client: appears while `activeVideoCall` is set, goes away
/// when it clears, hangs up if the person closes it first.
@MainActor
final class VideoCallPresenter {
    static let shared = VideoCallPresenter()

    private var shownFor: String?
    private var videoConnection: ((String) async -> CallSession?)?
    #if canImport(AppKit)
    private var window: NSWindow?
    private var closing: NSObjectProtocol?
    #else
    private var controller: UIViewController?
    #endif

    func install(host: NativeNetwork) {
        videoConnection = { [weak host] peer in await host?.videoConnection(peer: peer) }
        Client.shared.observe { [weak self] in MainActor.assumeIsolated { self?.reconcile() } }
    }

    private func reconcile() {
        let live = Client.shared.activeVideoCall
        if let live, shownFor != live.contactID {
            shownFor = live.contactID
            present(live)
        } else if live == nil, shownFor != nil {
            shownFor = nil
            dismiss()
        }
    }

    private func present(_ convo: Conversation) {
        let client = Client.shared
        Task { @MainActor in
            guard let transport = client.transport(for: convo.contactID),
                  let connection = await videoConnection?(transport) else { return }
            // Made once, before the media arrives: each view renders the
            // track that is, or later becomes, attached.
            let panel = VideoCallPanel(
                name: client.displayName(for: convo.contactID),
                remote: await connection.makeRemoteVideoView(),
                local: await connection.makeLocalVideoView(),
                end: { client.hangUp(in: convo) }
            )
            guard shownFor == convo.contactID else { return }
            show(panel, convo: convo)
        }
    }

    #if canImport(AppKit)
    private func show(_ panel: VideoCallPanel, convo: Conversation) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 480),
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false
        )
        window.title = panel.name
        window.titlebarAppearsTransparent = true
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: panel)
        window.center()
        window.makeKeyAndOrderFront(nil)
        self.window = window
        // The red button ends the call, as closing FaceTime does.
        closing = NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification, object: window, queue: .main
        ) { _ in
            MainActor.assumeIsolated {
                if Client.shared.activeVideoCall === convo { Client.shared.hangUp(in: convo) }
            }
        }
    }

    private func dismiss() {
        if let closing { NotificationCenter.default.removeObserver(closing) }
        closing = nil
        window?.close()
        window = nil
    }
    #else
    private func show(_ panel: VideoCallPanel, convo: Conversation, attempt: Int = 0) {
        // The "Calling…" alert is still animating away when the call goes
        // live; presenting over it fails silently. Wait it out.
        guard let top = QRStore.topController() else { NSLog("Convo video: no top controller"); return }
        NSLog("Convo video: show attempt %d top %@ presenting %d dismissing %d", attempt, String(describing: type(of: top)),
              top.presentedViewController == nil ? 0 : 1, top.isBeingDismissed ? 1 : 0)
        if top.presentedViewController != nil || top.isBeingDismissed {
            guard attempt < 20, shownFor == convo.contactID else { return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
                self?.show(panel, convo: convo, attempt: attempt + 1)
            }
            return
        }
        let controller = UIHostingController(rootView: panel)
        controller.modalPresentationStyle = .fullScreen
        top.present(controller, animated: true)
        self.controller = controller
        NSLog("Convo video: presented")
    }

    private func dismiss() {
        controller?.dismiss(animated: true)
        controller = nil
    }
    #endif
}

/// The call: them large, us small in a corner, a way out at the bottom.
struct VideoCallPanel: View {
    let name: String
    let remote: WebRTCVideoView
    let local: WebRTCVideoView
    let end: () -> Void

    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            VideoSurface(view: remote)
                .ignoresSafeArea()
            VideoSurface(view: local)
                .frame(width: 120, height: 160)
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(16)
        }
        .overlay(alignment: .top) {
            Text(name)
                .font(.headline)
                .foregroundColor(.white)
                .padding(.top, 12)
        }
        .overlay(alignment: .bottom) {
            Button("End", systemImage: "phone.down.fill", role: .destructive, action: end)
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .controlSize(.large)
                .padding(.bottom, 32)
        }
        .background(Color.black)
        #if canImport(AppKit)
        .frame(minWidth: 480, minHeight: 360)
        #endif
    }
}

/// A WebRTC video view in the SwiftUI tree.
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
