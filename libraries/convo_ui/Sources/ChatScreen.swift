import InboxUI
import MessagesUI
import NavigationUI
import ConvoApp
import ConvoMLS
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif
import Isomer
import Foundation

// The Convo UI: MessagesUI's inbox, thread, details pane and split layout,
// fed from the Client and wired to Convo's own ceremonies — pairing as a
// draft row whose content is the pairing flow, calls from the details
// pane (a menu in the bar on a phone), settings as a sheet or the Mac's
// application menu. Compiled natively for iOS and macOS, and to wasm and
// Android against the reimplemented SwiftUI, from this one source.
public struct ChatScreen: View {
    private var client = Client.shared
    @Environment(\.horizontalSizeClass) private var sizeClass
    @State private var selectedContact: String?
    @State private var settingsVisible = false
    @State private var columns: NavigationSplitViewVisibility = .automatic
    @State private var compactColumn: NavigationSplitViewColumn = .sidebar
    /// What is typed and not yet sent, per conversation.
    @State private var drafts: [String: String] = [:]

    public init() {}

    /// The inbox row for a pairing in progress: "New Conversation", as
    /// Messages' compose. It exists while the client has a pairing open,
    /// and the content pane shows the ceremony in its place.
    static let draftID = "new-conversation"
    private static let draftRow = ConversationSummary(
        id: draftID, name: "New Conversation", avatar: .symbol("person.fill"), preview: "Not paired yet"
    )

    private var draftActive: Bool { client.pairingVisible }
    private var inboxEmpty: Bool { client.conversations.isEmpty && !draftActive }

    /// A phone's single column: compose and the call live in the bars
    /// there; wider, compose is on the inbox's or the content's bar and
    /// the call in the details pane.
    private var compact: Bool { Platform.current != .macOS && sizeClass == .compact }

    /// Before there is an identity there is no inbox: onboarding stands
    /// alone, and the split view mounts once the client is up, so a phone
    /// starts on the inbox (an empty one has its own empty state).
    private var preferredCompactColumn: Binding<NavigationSplitViewColumn> {
        Binding(get: { compactColumn }, set: { compactColumn = $0 })
    }

    /// What the inbox has selected. While a pairing is open that is the
    /// draft row; when it finishes, the contact it produced; otherwise the
    /// person's pick (or what a test hook asked to open), and with nothing
    /// picked a wide layout opens the first conversation while a phone
    /// stays on the inbox. Picking another row while a pairing is open
    /// abandons it.
    private var selection: Binding<String?> {
        Binding(
            get: {
                if draftActive { return Self.draftID }
                if selectedContact == Self.draftID { return client.lastPairedContact }
                return selectedContact ?? client.debugOpenContact ?? client.restoredContact
                    ?? (compact ? nil : client.conversations.first?.contactID)
            },
            set: { picked in
                if picked != Self.draftID, draftActive { client.cancelPairing() }
                client.restoredContact = nil
                selectedContact = picked
                client.openContact = picked == Self.draftID ? nil : picked
            }
        )
    }

    private var openContactID: String? {
        guard let id = selection.wrappedValue, id != Self.draftID,
              client.conversation(with: id) != nil else { return nil }
        return id
    }

    private var infoPresented: Binding<Bool> {
        Binding(get: { client.detailsRequested }, set: { client.setDetails($0) })
    }

    private func compose() {
        selectedContact = Self.draftID
        client.openContact = nil
        client.pairingVisible = true
        compactColumn = .detail
    }

    public var body: some View {
        Group {
            if client.phase == .starting {
                StartingPlaceholder(diagnostics: client.diagnostics)
            } else if client.phase == .needsIdentity {
                OnboardingView(client: client)
            } else {
                split
            }
        }
        .task { client.startIfNeeded() }
    }

    private var split: some View {
        SplitView(columns: $columns, compactColumn: preferredCompactColumn,
                  inspectorPresented: infoPresented, compact: compact) {
            InboxView(conversations: client.conversations.map(summary), selection: selection) {
                if draftActive {
                    InboxCell(conversation: Self.draftRow)
                        .tag(Self.draftID)
                }
            }
            .overlay {
                if inboxEmpty {
                    EmptyDetail(title: "No conversations yet", subtitle: "Compose to pair with someone.")
                }
            }
            .navigationTitle("Inbox")
            .toolbarTitleDisplayMode(.inline)
            .inboxToolbar(showsCompose: compact, openSettings: { settingsVisible = true }, compose: compose)
        } detail: {
            detailPane
                .toolbar {
                    // Compose at the leading end of the content's bar, beside
                    // the sidebar, where Messages keeps it. A phone has it on
                    // the inbox instead.
                    if !compact {
                        ToolbarItem(placement: .navigation) {
                            Button("New Conversation", systemImage: "square.and.pencil", action: compose)
                        }
                    }
                }
        } inspector: {
            if let id = openContactID, let convo = client.conversation(with: id) {
                InspectorView(isPresented: client.detailsRequested, close: { client.setDetails(false) }) {
                    ContactInfo(client: client, convo: convo, close: { client.setDetails(false) })
                }
            }
        }
        // A pairing the client opened itself (an invite link, a scanned
        // code) selects the draft row the way Compose does, so when it
        // finishes the selection moves on to the new contact and a phone
        // lands in the new thread, not on an empty detail pane.
        .onChange(of: client.pairingVisible) { visible in
            if visible, selectedContact != Self.draftID {
                selectedContact = Self.draftID
                compactColumn = .detail
            }
        }
        // The conversation open before the page reloaded: a phone goes
        // back into it, as it was, rather than to the inbox (p2prc#10).
        .onChange(of: client.restoredContact) { restored in
            if restored != nil, selectedContact == nil, !draftActive { compactColumn = .detail }
        }
        // Settings is a sheet where there is no menu bar; the Mac app
        // offers it from its application menu instead.
        .sheet(isPresented: $settingsVisible) {
            SettingsView(client: client, close: { settingsVisible = false })
        }
    }

    @ViewBuilder private var detailPane: some View {
        if draftActive, selection.wrappedValue == Self.draftID {
            PairingView(client: client)
        } else if let id = openContactID, let convo = client.conversation(with: id) {
            thread(for: convo)
        } else {
            EmptyDetail(
                title: client.conversations.isEmpty ? "No conversations yet" : "Select a conversation",
                subtitle: client.conversations.isEmpty ? "Compose to pair with someone." : nil
            )
        }
    }

    private func thread(for convo: Conversation) -> some View {
        let id = convo.contactID
        let name = client.displayName(for: id)
        return ThreadView(
            conversation: summary(convo),
            messages: convo.messages.map { message in
                let content: MessageContent = if let image = message.image, let url = URL(string: image) {
                    .image(MediaItem(url: url, aspectRatio: CGFloat(message.aspect ?? 4.0 / 3.0)))
                } else {
                    .text(message.text)
                }
                var item = MessageItem(id: message.id, isMine: message.mine, content: content,
                                       timestamp: Date(timeIntervalSince1970: message.timestamp))
                item.reactions = (message.reactions ?? []).map { Reaction(emoji: $0.emoji, count: $0.count, mine: $0.mine) }
                return item
            },
            emptyText: convo.connected
                ? "Say something — only \(name) can read it."
                : "They're offline. Messages wait for them at the nodes.",
            footer: footer(convo),
            draft: Binding(get: { drafts[id] ?? "" }, set: { drafts[id] = $0 }),
            // A picture, where the host can pick one (a photo library, a
            // file chooser); reactions from a long press on a bubble.
            accessories: ComposerAccessories(leading: {
                if client.capabilities.picksImages {
                    Button(action: { client.sendImage(in: convo) }) {
                        Image(systemName: "plus.circle")
                            .font(.title2)
                            .foregroundColor(.accentColor)
                            .frame(minWidth: 36, minHeight: 36)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Photo")
                }
            }, trailing: { EmptyView() }),
            send: {
                client.send(drafts[id] ?? "", in: convo)
                drafts[id] = ""
            },
            onTitleTap: { client.toggleDetails() },
            onReact: { item, emoji in client.react(to: item.id, emoji: emoji, in: convo) }
        )
        .toolbar {
            // Top right, on a phone only: the call menu. Wider layouts keep
            // the call in the details pane, so the bar's items never shift
            // when the pane opens or closes.
            if compact {
                ToolbarItem(placement: .primaryAction) {
                    CallMenu(client: client, convo: convo)
                }
            }
        }
        .callAlerts(client: client, contactID: id)
    }

    /// Under the last message: where it stands (§5–§7), as Messages says
    /// "Delivered".
    private func footer(_ convo: Conversation) -> String? {
        if !convo.callNote.isEmpty { return convo.callNote }
        guard let last = convo.messages.last, last.mine else { return convo.unsound ? "History could not be verified" : nil }
        switch last.state {
        case "locked": return "Locked on the chain"
        case "attested": return "Attested"
        case "queued": return convo.connected ? "Delivered" : "Waiting for a node"
        default: return convo.connected ? "Delivered" : "Sent to the nodes"
        }
    }

    /// The inbox row (and the thread's title) for a conversation.
    private func summary(_ convo: Conversation) -> ConversationSummary {
        ConversationSummary(
            id: convo.contactID,
            name: client.displayName(for: convo.contactID),
            presence: convo.connected ? .online : .idle,
            preview: convo.messages.last?.text ?? "No messages yet",
            timestamp: convo.messages.last.map { Date(timeIntervalSince1970: $0.timestamp) }
        )
    }
}

private extension View {
    /// The inbox's bar items: settings (a gear, where there is no menu bar
    /// to hold it) and, on a phone, compose. The Mac's inbox carries no
    /// toolbar of its own (settings is in the application menu, compose
    /// on the content's bar).
    @ViewBuilder func inboxToolbar(showsCompose: Bool, openSettings: @escaping () -> Void,
                                   compose: @escaping () -> Void) -> some View {
        if Platform.current == .macOS {
            self
        } else {
            toolbar {
                ToolbarItem(placement: .navigation) {
                    Button("Settings", systemImage: "gearshape", action: openSettings)
                }
                if showsCompose {
                    ToolbarItem(placement: .primaryAction) {
                        Button("New Conversation", systemImage: "square.and.pencil", action: compose)
                    }
                }
            }
        }
    }
}

/// The detail column before the client is up.
struct StartingPlaceholder: View {
    let diagnostics: String

    var body: some View {
        VStack(spacing: 6) {
            Text("starting…")
                .font(.callout)
                .foregroundColor(Palette.secondaryText)
            Text(diagnostics)
                .font(.caption2)
                .foregroundColor(Palette.secondaryText)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("")
    }
}
