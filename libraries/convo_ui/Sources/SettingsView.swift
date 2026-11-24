import MessagesUI
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
// MARK: - Settings

/// Settings is the signaling-server list and nothing else: contacts are
/// named by whoever holds them, and your own fingerprint is in the
/// contact details, where the comparison happens. The Mac shows this in
/// its Settings window (from the application menu); elsewhere it is a
/// sheet with a Done button.
public struct SettingsView: View {
    var client: Client
    let close: (() -> Void)?
    @State private var newServer = ""
    @State private var phrase: String?
    @State private var confirmReset = false

    public init(client: Client, close: (() -> Void)?) {
        self.client = client
        self.close = close
    }

    public var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Identity: \(client.identityKey)").font(.caption)
                    if let phrase {
                        Text(phrase).font(.body)
                    } else {
                        Button("Show recovery phrase") { client.recoveryPhrase { phrase = $0.isEmpty ? "(imported from a secret key; no phrase)" : $0 } }
                    }
                    if confirmReset {
                        Text("Forget this identity on this device? Only the recovery phrase brings it back.").font(.callout)
                        Button("Yes, sign out", role: .destructive) { client.resetIdentity(); close?() }
                        Button("Keep it") { confirmReset = false }
                    } else {
                        Button("Sign out of this device", role: .destructive) { confirmReset = true }
                    }
                } header: {
                    Text("Identity")
                } footer: {
                    Text("Your identity is a key only you hold. The recovery phrase restores it on any device.")
                }
                // Another device becoming this identity: a code it scans.
                Section {
                    if client.handoffLink.isEmpty {
                        Button("Add a device") { client.presentHandoff() }
                    } else {
                        QRPane(image: client.handoffQRImage)
                        Button("Share Link") { client.shareHandoff() }
                        Button("Done") { client.endHandoff() }
                    }
                    if !client.handoffStatus.isEmpty {
                        Text(client.handoffStatus).font(.callout).foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Devices")
                } footer: {
                    Text("A phone and a Mac can be one identity. The new device gets your identity, your contacts and your conversations' keys; messages the nodes still hold come back to it.")
                }
                // The signaling servers this device has confirmed, and a way
                // to contribute one: a URL, told to every server we trust,
                // exactly as servers tell each other (docs/architecture.md).
                Section {
                    if client.signalingServers.isEmpty {
                        Text("None reachable yet")
                            .foregroundColor(Palette.secondaryText)
                    }
                    ForEach(client.signalingServers, id: \.url) { server in
                        LabeledContent(server.url, value: server.turn ? "relay" : "")
                    }
                    TextField("https://…", text: $newServer)
                    Button("Add server") {
                        client.advertiseServer(newServer)
                        newServer = ""
                    }
                    .disabled(newServer.isEmpty)
                } header: {
                    Text("Nodes")
                } footer: {
                    // 16pt below the inset grouped section on a phone (the
                    // form's own gap is half that).
                    Text("Nodes hold your messages for offline contacts, host the handshake when you pair, and offer STUN/TURN; \"relay\" means one offers TURN for networks that block direct connections. To run one, see convo_protocol's Dockerfile; it needs a public HTTPS URL. What you add here is checked before it is used, and shared with the other nodes.")
                        .padding(.top, Platform.current == .macOS ? 0 : 8)
                }
                Section {
                    LabeledContent("Version", value: Client.version)
                }
            }
            // The grouped form everywhere: the inset grouped list on a
            // phone and the web, the settings-window form on the Mac.
            .formStyle(.grouped)
            .navigationTitle("Settings")
            .toolbarTitleDisplayMode(.inline)
            .toolbar {
                if let close {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Close", systemImage: "xmark", action: close)
                    }
                }
            }
        }
        .settingsWindowSize()
    }
}

private extension View {
    /// A floor for the Mac's Settings window only. On a phone a minimum
    /// wider than the screen pushed the sheet's content past its edges.
    @ViewBuilder func settingsWindowSize() -> some View {
        if Platform.current == .macOS {
            frame(minWidth: 420, minHeight: 360)
        } else {
            self
        }
    }
}
