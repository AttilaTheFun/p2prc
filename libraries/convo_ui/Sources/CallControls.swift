import MessagesUI
import ConvoApp
import ConvoMLS
import SwiftUI
import Isomer

// MARK: - Calls
//
// The call lives in the contact's details, as Messages keeps FaceTime
// there: a row of round buttons under the name. A phone, with no details
// pane beside the chat, gets the same choices from a menu in the bar.

/// The details pane's row: audio and video to start; red to leave a call
/// we are in; green to join one we declined that is still going.
struct CallButtons: View {
    var client: Client
    let convo: Conversation

    var body: some View {
        HStack(spacing: 16) {
            switch convo.callState {
            case .none:
                round("Audio", "phone") { client.startCall(in: convo, video: false) }
                    .disabled(!convo.connected)
                round("Video", "video") { client.startCall(in: convo, video: true) }
                    .disabled(!convo.connected)
            case .declined:
                round("Join", "phone.fill") { client.acceptCall(in: convo) }
                    .tint(Palette.ok)
            case .outgoingRinging, .incomingRinging, .active:
                round("End", "phone.down.fill", role: .destructive) { client.hangUp(in: convo) }
                    .tint(Palette.danger)
            }
        }
    }

    private func round(_ title: String, _ symbol: String, role: ButtonRole? = nil,
                       action: @escaping () -> Void) -> some View {
        Button(title, systemImage: symbol, role: role, action: action)
            .labelStyle(.iconOnly)
            .secondaryButton()
            .buttonBorderShape(.circle)
            .controlSize(.large)
    }
}

/// The phone's bar item: a menu of the same choices while there is no
/// call, the one button that matters while there is.
struct CallMenu: View {
    var client: Client
    let convo: Conversation

    var body: some View {
        switch convo.callState {
        case .none:
            Menu {
                Button("Audio Call", systemImage: "phone") { client.startCall(in: convo, video: false) }
                Button("Video Call", systemImage: "video") { client.startCall(in: convo, video: true) }
            } label: {
                Label("Call", systemImage: "phone")
            }
            .disabled(!convo.connected)
        case .declined:
            Button("Join Call", systemImage: "phone.fill") { client.acceptCall(in: convo) }
                .tint(Palette.ok)
        case .outgoingRinging, .incomingRinging, .active:
            Button("End Call", systemImage: "phone.down.fill", role: .destructive) { client.hangUp(in: convo) }
                .tint(Palette.danger)
        }
    }
}

extension View {
    /// Ringing out: "Calling…" with Cancel. Ringing in: Accept or Decline.
    /// Declining keeps the call joinable from the (green) button while
    /// they are still calling.
    func callAlerts(client: Client, contactID: String) -> some View {
        let convo = client.conversation(with: contactID)
        return self
            .alert("Calling…", isPresented: Binding(
                get: { convo?.callState == .outgoingRinging },
                set: { _ in }
            )) {
                Button("Cancel", role: .cancel) { if let convo { client.hangUp(in: convo) } }
            } message: {
                Text(client.displayName(for: contactID))
            }
            .alert("Incoming Call", isPresented: Binding(
                get: { if case .incomingRinging = convo?.callState { return true } else { return false } },
                set: { _ in }
            )) {
                Button("Accept") { if let convo { client.acceptCall(in: convo) } }
                Button("Decline", role: .cancel) { if let convo { client.declineCall(in: convo) } }
            } message: {
                Text(client.displayName(for: contactID))
            }
    }
}
