#if os(macOS)
import AppKit
import MessagesUI
import ConvoApp
import ConvoUI
import ShakeKit
import SwiftUI
import UpdateKit

/// Convo on macOS: an ordinary document-less app, like Messages — a Dock
/// icon, one window, quit from the menu. Compiled native Swift, real
/// SwiftUI; the client runs in-process with the host installed at launch,
/// and the OS drives dark mode.
@main
struct ConvoMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        WindowGroup {
            // No `.frame(minWidth:)` on the window's content: a minimum
            // there fights the split view's own column minimums, and the
            // control app (tools/lab/split_inspector) shows it is the one
            // thing that makes the layout jump for a frame when the
            // inspector opens; it is also the min-size path AppKit looped
            // in when the pane crashed. The columns' minimums are the floor.
            ChatScreen()
                .shakeToReport(repository: "AttilaTheFun/p2prc")
        }
        .defaultSize(width: 960, height: 640)
        // Help › Report a Bug… (⌥⌘B): an issue in Convo's repository.
        .commands { ShakeKitCommands() }
        // Settings…, in the application menu, as every Mac app has it.
        Settings {
            SettingsView(client: Client.shared, close: nil)
                .frame(width: 520, height: 380)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let host = NativeNetwork(qr: QRStore.shared)

    func applicationDidFinishLaunching(_ notification: Notification) {
        // The build this is, told to Applications (in the team's own builds;
        // without the app group it does nothing).
        AppUpdates.start()
        // Install the host and start the client now, so the first render
        // finds a networking stack.
        ConvoNativeHost.install(host: host)
        VideoCallPresenter.shared.install(host: host)
        Client.shared.startIfNeeded()
        installTitlebarAccessory()
        installDebugPairing()
    }

    // MARK: - The conversation title

    /// Messages' title on the Mac, as MessagesUI's titlebar accessory: it
    /// follows the shown conversation and toggles the details when clicked.
    private let titlebar = MacConversationTitlebar()

    private func installTitlebarAccessory() {
        titlebar.onTap = { Client.shared.toggleDetails() }
        titlebar.install()
        Client.shared.observe { [weak self] in MainActor.assumeIsolated { self?.refreshTitle() } }
        refreshTitle()
    }

    private func refreshTitle() {
        let client = Client.shared
        if let id = client.shownContact, let convo = client.conversation(with: id) {
            let name = client.displayName(for: id)
            titlebar.title = (name, .initial(name), convo.connected ? .online : .idle)
        } else {
            titlebar.title = nil
        }
    }

    // MARK: - Debug pairing (dev only)

    /// `CONVO_DEBUG_PAIRING=1` turns this instance into a hands-free pairing
    /// presenter for end-to-end testing: it invites on launch, accepts an
    /// incoming call, names the new contact, and prints every observable
    /// transition to stdout — the pairing code included, which is why this
    /// must never be on outside a test. The Mac's own AX tree is unusable
    /// for UI driving (SwiftUI accessory apps expose a degenerate tree), so
    /// this stdout stream is the automation surface, the same role the web
    /// client's `__convoState()` hook plays in a browser.
    private var debugTimer: Timer?

    private var debugActivity: NSObjectProtocol?

    private func installDebugPairing() {
        guard ProcessInfo.processInfo.environment["CONVO_DEBUG_PAIRING"] == "1" else { return }
        setbuf(stdout, nil)   // launched with stdout to a file; don't buffer
        // A hidden accessory app gets App Napped: timers stop, the code stops
        // rotating, the mailbox poll stalls, and the presenter looks dead.
        debugActivity = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiated, .idleSystemSleepDisabled],
            reason: "CONVO_DEBUG_PAIRING end-to-end test"
        )
        let client = Client.shared
        print("DEBUG pairing hook armed")

        // One observer over the client: each published value is printed
        // when it changes (the sinks it replaces fired on every publish);
        // the conversations on every change, as before.
        var seenPhase: Client.Phase? = nil
        var seenLink = "", seenStatus = "", seenNaming: String? = nil
        let report: () -> Void = {
            if client.phase != seenPhase {
                seenPhase = client.phase
                print("DEBUG phase: \(client.phase)")
                // A test run creates its identity by itself.
                if client.phase == .needsIdentity { DispatchQueue.main.async { _ = client.createIdentity(); print("DEBUG identity created") } }
            }
            if client.inviteLink != seenLink {
                seenLink = client.inviteLink
                if !seenLink.isEmpty { print("DEBUG inviteLink: \(seenLink)") }
            }
            if client.status != seenStatus {
                seenStatus = client.status
                if !seenStatus.isEmpty { print("DEBUG status: \(seenStatus)") }
            }
            if client.pendingNaming != seenNaming {
                seenNaming = client.pendingNaming
                if let naming = seenNaming {
                    print("DEBUG naming: \(naming) -> Droid")
                    DispatchQueue.main.async { client.renameContact(naming, to: "Droid") }
                }
            }
            for convo in client.conversations {
                let last = convo.messages.last.map { "\($0.mine ? ">" : "<") \($0.text)" } ?? "-"
                print("DEBUG conv \(convo.id.prefix(8)) connected=\(convo.connected) "
                    + "call=\(convo.callState) msgs=\(convo.messages.count) last=\(last) "
                    + "states=\(convo.messages.map(\.state)) chain=\(convo.chainStatus)")
                if case .incomingRinging = convo.callState {
                    print("DEBUG accepting call")
                    DispatchQueue.main.async { client.acceptCall(in: convo) }
                }
            }
        }
        client.observe(report)
        report()

        // CONVO_DEBUG_DETAILS=1: open the details at 8s and close them at
        // 12s, so the pane's animations can be sampled with no pointer.
        if ProcessInfo.processInfo.environment["CONVO_DEBUG_DETAILS"] == "1" {
            DispatchQueue.main.asyncAfter(deadline: .now() + 8) { client.setDetails(true) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 12) { client.setDetails(false) }
        }
        // Open an existing conversation if no pairing names a new one, so a
        // screenshot of the chat page needs no taps. (Fall back to opening
        // whatever conversation is first.)
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
            if client.debugOpenContact == nil, let first = client.conversations.first {
                client.debugOpenContact = first.contactID
            }
        }
        // CONVO_DEBUG_JOIN=<fragment>: act as the scanner of that invite
        // instead of inviting. CONVO_DEBUG_CALL=audio|video: once the peer
        // channel is up, place that call. CONVO_DEBUG_SEND=<text>: once
        // connected, send that message.
        let join = ProcessInfo.processInfo.environment["CONVO_DEBUG_JOIN"] ?? ""
        let call = ProcessInfo.processInfo.environment["CONVO_DEBUG_CALL"] ?? ""
        let text = ProcessInfo.processInfo.environment["CONVO_DEBUG_SEND"] ?? ""
        // CONVO_DEBUG_FORK=1: once the group is locked, start a recovery
        // fork as if the lock had been unsound.
        let fork = ProcessInfo.processInfo.environment["CONVO_DEBUG_FORK"] == "1"
        var joined = false, called = false, sent = false, forked = false
        debugTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
            MainActor.assumeIsolated {
                if !join.isEmpty {
                    if !joined, client.phase == .idle {
                        joined = true
                        print("DEBUG joining")
                        client.pairingVisible = true
                        client.acceptInvite(fragment: join.hasPrefix("#c=") ? String(join.dropFirst(3)) : join)
                    }
                } else if client.inviteLink.isEmpty, client.phase == .idle {
                    print("DEBUG inviting")
                    client.invite()
                }
                if !call.isEmpty, !called, let convo = client.conversations.first(where: { $0.connected }) {
                    called = true
                    print("DEBUG calling \(call)")
                    client.startCall(in: convo, video: call == "video")
                }
                // CONVO_DEBUG_SEND_OFFLINE=1: send to the first conversation
                // whether or not the peer is on the channel (mailbox delivery).
                let offline = ProcessInfo.processInfo.environment["CONVO_DEBUG_SEND_OFFLINE"] == "1"
                if !text.isEmpty, !sent, let convo = client.conversations.first(where: { offline || $0.connected }) {
                    sent = true
                    print("DEBUG sending")
                    client.send(text, in: convo)
                }
                if fork, !forked, let convo = client.conversations.first(where: { $0.chainStatus.hasPrefix("all ") }) {
                    forked = true
                    print("DEBUG forking")
                    client.beginRecoveryFork(convo)
                }
                if joined || !client.inviteLink.isEmpty, call.isEmpty || called, text.isEmpty || sent, !fork || forked { self.debugTimer?.invalidate() }
            }
        }
    }

}

#endif
