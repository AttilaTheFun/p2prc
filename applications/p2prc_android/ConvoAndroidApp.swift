import ConvoUI
import SwiftUI

/// The Convo Android client's entry point.
///
/// The whole UI lives in `ConvoUI` (shared with every other client); this
/// target cross-compiles it against isomer's portable SwiftUI with the
/// hermetic NDK toolchain, rendered by the Jetpack Compose renderer. It
/// performs no I/O of its own: transport and platform APIs arrive through the
/// injected `ConvoHost` (the Kotlin host in `AppServices.kt`), and everything
/// else — identity, the MLS group, every byte of plaintext — stays in Swift.
@main
public struct ConvoAndroidApp: App {
    public init() {}

    public var body: some Scene {
        WindowGroup {
            ChatScreen()
        }
    }
}
