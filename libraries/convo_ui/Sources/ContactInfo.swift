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
/// The contact's details, inside NavigationUI's InspectorView: who this is,
/// live, the call, both keys, and unpairing.
struct ContactInfo: View {
    var client: Client
    let convo: Conversation
    let close: () -> Void
    @State private var confirmingUnpair = false
    @State private var editingName = false
    @State private var newName = ""

    var body: some View {
        details
    }

    private var details: some View {
        ScrollView {
            VStack(spacing: 18) {
                Avatar(.initial(client.displayName(for: convo.contactID)), size: 72,
                       presence: convo.connected ? .online : .idle)
                if editingName {
                    HStack {
                        TextField("Name", text: $newName)
                        Button("Save") { client.renameContact(convo.contactID, to: newName); editingName = false }
                            .disabled(newName.isEmpty)
                        Button("Cancel") { editingName = false }
                    }
                    .frame(maxWidth: 320)
                } else {
                    Text(client.displayName(for: convo.contactID))
                        .font(.title2.weight(.semibold))
                        .foregroundColor(Palette.text)
                    Button("Rename") { newName = client.contact(convo.contactID)?.name ?? ""; editingName = true }
                        .font(.caption)
                }
                CallButtons(client: client, convo: convo)

                // While the link is down: what the reconnect is doing, and
                // a way to kick it from this side.
                if !convo.connected {
                    if !convo.linkStatus.isEmpty {
                        Text(convo.linkStatus)
                            .font(.caption2)
                            .foregroundColor(Palette.secondaryText)
                            .multilineTextAlignment(.center)
                    }
                    Button("Reconnect Now", systemImage: "arrow.clockwise") { client.reconnectNow(convo) }
                        .secondaryButton()
                        .buttonBorderShape(.capsule)
                }


                VStack(alignment: .leading, spacing: 6) {
                    Text("key")
                        .font(.caption)
                        .foregroundColor(Palette.secondaryText)
                    HStack(spacing: 6) {
                        Text(Client.displayFingerprint(convo.contactID))
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundColor(Palette.text)
                        if convo.peerVerified {
                            Image(systemName: "checkmark.seal.fill")
                                .font(.caption)
                                .foregroundColor(Palette.ok)
                        }
                    }
                    Text(convo.peerVerified
                        ? "Their signed KeyPackage and the group's MLS commit prove they hold this key."
                        : "Compare fingerprints aloud to rule out an impostor.")
                        .font(.caption2)
                        .foregroundColor(Palette.secondaryText)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 12).fill(Palette.secondaryText.opacity(0.12)))

                // Your own, beside theirs: the comparison is read aloud
                // both ways.
                VStack(alignment: .leading, spacing: 6) {
                    Text("your key")
                        .font(.caption)
                        .foregroundColor(Palette.secondaryText)
                    Text(client.selfFingerprint)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(Palette.text)
                    Text("What their screen shows for you.")
                        .font(.caption2)
                        .foregroundColor(Palette.secondaryText)
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 12).fill(Palette.secondaryText.opacity(0.12)))

                // Two taps to unpair: the second confirms. Their side keeps
                // its copy until they do the same.
                if confirmingUnpair {
                    VStack(spacing: 8) {
                        Text("Remove this contact and its messages from this device?")
                            .font(.caption)
                            .foregroundColor(Palette.secondaryText)
                            .multilineTextAlignment(.center)
                        HStack(spacing: 12) {
                            Button("Keep") { confirmingUnpair = false }
                                .secondaryButton()
                            Button("Unpair", role: .destructive) {
                                confirmingUnpair = false
                                close()
                                client.unpair(convo.contactID)
                            }
                            .prominentButton()
                        }
                        .buttonBorderShape(.capsule)
                    }
                    .padding(.top, 8)
                } else {
                    Button("Unpair", role: .destructive) { confirmingUnpair = true }
                        .buttonStyle(.borderless)
                        .padding(.top, 8)
                }
            }
            .padding(16)
        }
        .frame(minWidth: 260)
    }
}
