import ConvoServices
import IsomerFFI

/// Installs the native networking stack as the client's injected `ConvoHost`.
///
/// The compiled apps run the client in-process, so this is plain swift_ffi
/// dependency injection — the same `installDependencies` the example apps use
/// for their compiled cells. The client resolves `ConvoHost` from the
/// dependency dictionary on first use (a `Lazy`, so the host is built then),
/// and every completion/event is a direct call, no wasm boundary.
enum ConvoNativeHost {
    /// Install a host the caller already built (macOS keeps a reference for
    /// its menu status line).
    @MainActor
    static func install(host: NativeNetwork) {
        installDependencies([
            ConvoDependencyKey.host: Lazy<any ConvoHost> { host }
        ])
    }

    /// Install a host built on first resolution (iOS, which needs no
    /// reference to it).
    static func install(qr: QRStore) {
        installDependencies([
            ConvoDependencyKey.host: Lazy<any ConvoHost> {
                MainActor.assumeIsolated { NativeNetwork(qr: qr) }
            }
        ])
    }
}
