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
// MARK: - Pairing

/// The ceremony, in the content pane behind the inbox's "New Conversation"
/// row: choose to show or scan, then the code, then the name.
struct PairingView: View {
    var client: Client

    var body: some View {
        Group {
            if let naming = client.pendingNaming {
                NamingPane(client: client, contactID: naming)
            } else {
                switch client.phase {
                case .inviting:
                    InvitePane(client: client)
                case .joining:
                    JoiningPane(client: client)
                case .failed(let reason):
                    VStack(spacing: 8) {
                        Spacer()
                        Text("Something went wrong")
                            .font(.headline)
                            .foregroundColor(Palette.text)
                        Text(reason)
                            .font(.caption)
                            .foregroundColor(Palette.secondaryText)
                        Spacer()
                    }
                default:
                    ChoicePane(client: client)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(title)
        .toolbarTitleDisplayMode(.inline)
    }

    private var title: String {
        client.pendingNaming != nil ? "Name Contact" : "Pair"
    }
}


/// The pairing sheet's first screen: show a code or scan one.
struct ChoicePane: View {
    var client: Client

    var body: some View {
        VStack(spacing: 12) {
            Spacer()
            Text("Pair with someone")
                .font(.title3).bold()
                .foregroundColor(Palette.text)
            VStack(spacing: 2) {
                Text("One shows a code, the other scans it.")
                Text("Your keys never leave your devices.")
            }
            .font(.caption)
            .foregroundColor(Palette.secondaryText)
            Spacer().frame(height: 16)
            Button(action: { client.invite() }) {
                Text("Show a Pairing Code").frame(maxWidth: .infinity)
            }
            .prominentButton()
            if client.capabilities.scansQR {
                Button(action: { client.scanInvite() }) {
                    Text("Scan a Pairing Code").frame(maxWidth: .infinity)
                }
                .secondaryButton()
            }
            Spacer()
        }
        .controlSize(.large)
        .buttonBorderShape(.capsule)
        .frame(maxWidth: 320)
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 20)
    }
}

// MARK: - Inviting

struct InvitePane: View {
    var client: Client
    /// "QB3RSZ" → "QB3 RSZ": grouped the way people read codes aloud.

    var body: some View {
        VStack(spacing: 0) {
            // Connect: the picture and the two ways to hand it over.
            Text("Scan the code or open the link to connect")
                .font(.subheadline)
                .foregroundColor(Palette.secondaryText)
                .padding(.top, 8)

            QRPane(image: client.inviteQRImage)

            HStack(spacing: 12) {
                Button("Share Link") { client.shareInvite() }
                    .prominentButton()
                Button("Save Code") { client.saveInviteCode() }
                    .secondaryButton()
            }
            .controlSize(.large)
            .buttonBorderShape(.capsule)

            // Pair: the spoken code, which never travels in the QR. Reading it
            // off this screen and typing it on the other is what proves the
            // person was really shown it.
            VStack(spacing: 6) {
                Text(client.status.isEmpty ? "The conversation starts when they scan" : client.status)
                    .font(.subheadline)
                    .foregroundColor(Palette.secondaryText)
                Text(client.selfFingerprint)
                    .font(.system(size: 20, weight: .semibold, design: .monospaced))
                    .foregroundColor(Palette.text)
                    .padding(.top, 4)
            }
            .padding(.top, 24)

            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 20)
    }
}

/// The code, in the sheet's own tree, loaded from the URL the host
/// rendered it at: a temporary file on the native apps, a data URL on the
/// web. One path everywhere, no view injected from outside the library.
/// The card stays white in both schemes: a QR is read by a camera, and
/// inverting it costs scans on some readers.
struct QRPane: View {
    let image: String

    var body: some View {
        Group {
            if let url = URL(string: image), !image.isEmpty {
                AsyncImage(url: url) { img in
                    // Rendered at ten pixels a module, so the modest
                    // downscale keeps the modules crisp without
                    // `.interpolation(.none)` (not in the reimplementation).
                    img
                        .resizable()
                        .scaledToFit()
                } placeholder: {
                    Color.white
                }
                .padding(12)
                .background(RoundedRectangle(cornerRadius: 18).fill(Color.white))
            } else {
                Text("preparing…")
                    .font(.caption)
                    .foregroundColor(Palette.secondaryText)
            }
        }
        .frame(width: 264, height: 264)
        .padding(.vertical, 14)
    }
}

// MARK: - Joining

/// The joiner's half of pairing: type the code off their screen. Mesh pairing
/// completes on its own once the code is entered — the answer travels back
/// through the server's mailbox — so there is nothing to show or send here.
struct JoiningPane: View {
    var client: Client

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            VStack(spacing: 14) {
                Text("Connecting")
                    .font(.title3).bold()
                    .foregroundColor(Palette.text)
                Text("Setting up the conversation through the nodes")
                    .font(.subheadline)
                    .foregroundColor(Palette.secondaryText)
                Text(client.peerFingerprint)
                    .font(.system(size: 20, weight: .semibold, design: .monospaced))
                    .foregroundColor(Palette.text)
                if !client.status.isEmpty {
                    Text(client.status)
                        .font(.caption)
                        .foregroundColor(Palette.secondaryText)
                }
                Button("Cancel") { client.cancelPairing() }
                    .buttonStyle(.borderless)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 20)
    }
}


struct NamingPane: View {
    var client: Client
    let contactID: String
    @State private var name = ""

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            VStack(spacing: 14) {
                Text("Paired!")
                    .font(.title3).bold()
                    .foregroundColor(Palette.text)
                Text("What do you want to call them?")
                    .font(.subheadline)
                    .foregroundColor(Palette.secondaryText)

                TextField(client.defaultName(for: contactID), text: $name)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 22, weight: .semibold))
                    .multilineTextAlignment(.center)
                    .frame(width: 240)

                Button(action: { client.renameContact(contactID, to: name) }) {
                    Text("Save").frame(maxWidth: .infinity)
                }
                .prominentButton()
                .controlSize(.large)
                .buttonBorderShape(.capsule)
                .frame(width: 240)

                Button("Skip") { client.renameContact(contactID, to: "") }
                    .buttonStyle(.borderless)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 20)
    }
}

/// A key fingerprint, displayed to be compared: two people reading these
/// aloud between screens is the check no intermediary can fake.
