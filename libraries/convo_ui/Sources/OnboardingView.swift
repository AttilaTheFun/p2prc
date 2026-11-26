import ConvoApp
import SwiftUI
import Isomer

/// The first screen: the person makes an identity (and sees its recovery
/// phrase once), imports one they have, or takes one from another device.
struct OnboardingView: View {
    var client: Client
    @State private var mode: Mode = .choose
    @State private var phrase: [String] = []
    @State private var entry = ""
    @State private var problem: String?
    @State private var saved = false
    @State private var copied = false

    enum Mode { case choose, created, importing, handoff }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                switch mode {
                case .choose:
                    Text("Your identity").font(.title2.weight(.semibold))
                    Text("P2PRC signs everything you send with a key that only you hold. No account, no phone number: create a new identity here, or bring back one you already have with its recovery phrase.")
                        .foregroundStyle(.secondary)
                    Button("Create a new identity") { phrase = client.createIdentityPreview(); copied = false; mode = .created }
                        .prominentButton()
                    Button("Import an identity") { mode = .importing }
                        .secondaryButton()
                    Button("Use another device") { mode = .handoff }
                        .secondaryButton()
                case .handoff:
                    Text("Use another device").font(.title2.weight(.semibold))
                    Text("On the device that already has P2PRC, open Settings and choose \"Add a device\". Then scan its code here, or paste the link it shares.")
                        .foregroundStyle(.secondary)
                    if client.capabilities.scansQR {
                        Button("Scan the code") { client.scanInvite() }
                            .prominentButton()
                    }
                    TextField("or paste the link", text: $entry)
                    Button("Continue") { client.acceptHandoff(fragment: entry) }
                        .prominentButton()
                        .disabled(entry.isEmpty)
                    if !client.handoffStatus.isEmpty { Text(client.handoffStatus).font(.callout).foregroundStyle(.secondary) }
                    Button("Back") { mode = .choose; entry = "" }
                        .secondaryButton()
                case .created:
                    Text("Your recovery phrase").font(.title2.weight(.semibold))
                    Text("Write these 12 words down, in order, or put them in your password manager. They are the only way to get this identity back.")
                        .foregroundStyle(.secondary)
                    PhraseGrid(words: phrase)
                    // The words alone, in order, space-separated: the grid's
                    // numbers make selecting them by hand awkward.
                    Button(copied ? "Copied" : "Copy to clipboard", systemImage: copied ? "checkmark" : "doc.on.doc") {
                        client.copyToClipboard(phrase.joined(separator: " "))
                        copied = true
                    }
                    .secondaryButton()
                    Toggle("I have saved my recovery phrase", isOn: $saved)
                    Button("Continue") { _ = client.importIdentity(phrase: phrase.joined(separator: " ")) }
                        .prominentButton()
                        .disabled(!saved)
                    Button("Back") { client.cancelIdentityPreview(); mode = .choose; saved = false }
                        .secondaryButton()
                case .importing:
                    Text("Import an identity").font(.title2.weight(.semibold))
                    Text("Paste your 12- or 24-word recovery phrase, or your secret key in hex.")
                        .foregroundStyle(.secondary)
                    TextField("recovery phrase or secret key", text: $entry)
                    if let problem { Text(problem).foregroundStyle(.red).font(.callout) }
                    Button("Import") { problem = client.importIdentity(phrase: entry) }
                        .prominentButton()
                        .disabled(entry.isEmpty)
                    Button("Back") { mode = .choose; problem = nil }
                        .secondaryButton()
                }
            }
            .padding(24)
            .frame(maxWidth: 480)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // The phrase shown before the page reloaded, back where it was.
        .onAppear { resumePreview() }
        .onChange(of: client.previewPhrase) { _ in resumePreview() }
    }

    private func resumePreview() {
        guard mode == .choose, !client.previewPhrase.isEmpty else { return }
        phrase = client.previewPhrase
        copied = false
        mode = .created
    }
}

struct PhraseGrid: View {
    let words: [String]
    var body: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 8) {
            ForEach(Array(words.enumerated()), id: \.offset) { i, w in
                HStack(spacing: 6) {
                    Text("\(i + 1).").foregroundStyle(.secondary).font(.caption)
                    Text(w).font(.body)
                }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(.secondary.opacity(0.1)))
    }
}
