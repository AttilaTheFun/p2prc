import ConvoUI
import SwiftUI

/// The Convo web client's entry point.
///
/// The whole UI lives in `ConvoUI` (shared with the compiled iOS and macOS
/// apps); this target only compiles it to WebAssembly against isomer's
/// portable SwiftUI, rendered by the React renderer. It performs no I/O of its
/// own: transport and browser APIs arrive through the injected `ConvoHost`
/// (the JavaScript host in `index.html`), and everything else — identity, the
/// MLS group, every byte of plaintext — stays inside the wasm module.
@main
public struct ConvoClientApp: App {
    public init() {}

    public var body: some Scene {
        WindowGroup {
            ChatScreen()
        }
    }
}
