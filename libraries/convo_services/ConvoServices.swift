import IsomerFFI

/// The service surface the page injects into the wasm client.
///
/// Nothing inside a wasm bundle can open a socket, reach a WebRTC stack, or
/// touch localStorage — WASI has none of it. So every side effect crosses this
/// boundary and nothing else does: the host owns the transport and the browser
/// APIs, the guest owns identity, group state, and all crypto. No key material
/// crosses in either direction.
@ExportedEnum
public enum ConvoDependencyKey: String {
    case host
}

/// Async by convention: calls that produce a result carry a `requestID`, and
/// the host answers later through `convoRequestComplete`. Anything the host
/// initiates arrives through `convoEvent`.
@ExportedInterface(namespace: "convo")
public protocol ConvoHost {
    // Transport calls are scoped by `peer`: an opaque connection id the guest
    // chooses, so one client can hold live links to several peers at once.
    // The host keeps one connection per id; reusing an id replaces its
    // connection (which is how a reconnect swaps in a fresh link). Events
    // come back with the same id prefixed to the payload.

    /// Creates a WebRTC offer and gathers ICE. Completes with the packed blob.
    func createOffer(requestID: Int32, peer: String)
    /// Takes a remote offer, answers it, gathers ICE. Completes with our blob.
    func acceptOffer(requestID: Int32, peer: String, blob: String)
    /// Applies the answer to the offer we are holding open.
    func acceptAnswer(requestID: Int32, peer: String, blob: String)
    /// Sends one frame over the open data channel.
    func sendFrame(peer: String, text: String)
    /// Tears down one peer's connection and frees its resources.
    func closeConnection(peer: String)

    /// Persists a value (localStorage).
    func save(key: String, value: String)
    /// Reads a persisted value; completes with "" when absent.
    func load(requestID: Int32, key: String)
    /// Persists a secret (the identity's key material): the platform
    /// keychain where there is one; an empty value removes it.
    func saveSecret(key: String, value: String)
    /// Reads a secret; completes with "" when absent.
    func loadSecret(requestID: Int32, key: String)

    /// The page's own URL, minus any fragment — the base for pairing links.
    func pageURL(requestID: Int32)
    /// The fragment the page was opened with, so a link can auto-pair.
    func openingHash(requestID: Int32)
    /// Puts the invite blob in our address bar, so it is copyable and shareable.
    func setHash(value: String)

    /// Renders a QR code for `text` into the element with the given id.
    func drawQR(elementID: String, text: String)

    /// Renders a QR code for `text` as an image the UI loads into its own
    /// tree: completes with a URL an `AsyncImage` can fetch — a temporary
    /// PNG file on the native apps, a `data:image/png;base64,…` URL on the
    /// web.
    func qrImage(requestID: Int32, text: String)

    /// Hands text to whatever the platform uses to pass things along — a
    /// share sheet, a clipboard, a Web Share dialog.
    func share(text: String)

    /// Puts `text` on the platform clipboard (the pasteboard on Apple
    /// platforms, the Clipboard API in a browser, ClipboardManager on
    /// Android).
    func copyText(text: String)

    /// Saves the rendered code as an image.
    func saveQR(elementID: String)

    /// Asks the platform for a QR code from a picture: choose from the
    /// camera roll or take one, decode it on this device, complete with the
    /// decoded text. The image and its contents never leave the machine —
    /// which is the entire point of pairing by pictures.
    func scanQR(requestID: Int32)

    // MARK: - Networking stack
    //
    // The wasm module is identical on every client; only the stack underneath
    // differs. Everything below is mechanical: fetch this URL, wait this
    // long, hand the WebRTC stack these ICE servers. No decisions live here.
    // Which signaling server to use, when to health-check it, when to fall
    // back to a public STUN server — all of that is policy, and policy is in
    // the guest, so that every client makes the same choices everywhere.

    /// The stack's capabilities as JSON (NetworkCapabilities): what the
    /// platform can do that the shared UI should show or hide.
    func capabilities(requestID: Int32)

    /// Fetches a URL and completes with the body.
    func httpGet(requestID: Int32, url: String)

    /// POSTs `body` (JSON, or a sealed blob) to a URL and completes with the
    /// response body; fails on a non-2xx status.
    func httpPost(requestID: Int32, url: String, body: String)
    /// The node API speaks binary (borsh); bodies cross this boundary as
    /// base64 both ways. `httpPostBytes` sends `application/octet-stream`.
    func httpGetBytes(requestID: Int32, url: String)
    /// A member-only or auditor-only GET (protocol §19, revision 2): `auth`
    /// is the `X-Convo-Auth` header's value. Completes like `httpGetBytes`.
    func httpGetBytesSigned(requestID: Int32, url: String, auth: String)

    /// Lets the person choose a picture (the photo library, a file chooser)
    /// and completes with `<mime>|<width>|<height>|<base64 bytes>`, downscaled by the host to
    /// at most 1600px on the long side and re-encoded as JPEG; fails when
    /// nothing was chosen.
    func pickImage(requestID: Int32)
    /// Makes image bytes showable by `AsyncImage`: completes with a URL (a
    /// file in the app's cache, a blob: URL in a browser) good for the
    /// session. `key` names the image so the same bytes are kept once.
    func imageURL(requestID: Int32, key: String, bytes64: String, mime: String)
    func httpPostBytes(requestID: Int32, url: String, body64: String)

    /// The signaling servers this app shell was built with, comma-separated
    /// (docs/architecture.md §4): configuration shipped as data — an
    /// Info.plist key, an Android resource, a meta tag on the page — so no
    /// provider is baked into the client. Seeds are health-checked like any
    /// other server, never taken on faith.
    func seeds(requestID: Int32)

    /// Completes after roughly `ms` milliseconds. WASI hands the guest no
    /// timer, so waiting is a side effect like any other and crosses the
    /// boundary. When to wait, and for how long, stays policy — in the guest.
    func delay(requestID: Int32, ms: Int32)

    /// Hands the WebRTC stack its ICE server list (JSON array of URLs like
    /// "stun:host:port"). The guest decides the order — peers first, public
    /// fallbacks last — and refreshes it as the directory changes.
    func setIceServers(json: String)

    // MARK: - Calls
    //
    // Mechanical, like the rest: capture a microphone, add a track, apply
    // SDP the peer sent over the already-authenticated channel. When to
    // call, who answered, what state to show — all guest policy.

    /// Adds a local audio track (and the camera, for a video call) and
    /// completes with a renegotiation offer.
    func callStart(requestID: Int32, peer: String, video: Bool)
    /// Applies remote call SDP. If it is an offer, adds our own media
    /// (camera too when `video`) and completes with our answer; if an
    /// answer, completes with "".
    func callApplyRemote(requestID: Int32, peer: String, sdp: String, isOffer: Bool, video: Bool)
    /// Tears the call down: stop capture, drop the tracks.
    func callEnd(peer: String)
}

/// Resolves the injected host, or nil when running without one (SwiftUI
/// previews and the compiled-native build both hit this path).
public enum ConvoServices {
    /// Resolved on demand, and cached only once it succeeds.
    ///
    /// Not a lazy `static var`: that caches whatever it sees the first time,
    /// and the two hosts install dependencies at different points relative to
    /// the guest's `@main`. The browser installs before the app starts; a
    /// native host starts the reactor first and installs after. Caching a
    /// premature `nil` would leave the native client permanently hostless.
    public static var host: (any ConvoHost)? {
        if let resolved = resolvedHost { return resolved }
        resolvedHost = (dependencies[ConvoDependencyKey.host] as? Lazy<any ConvoHost>)?.value
        return resolvedHost
    }

    private static var resolvedHost: (any ConvoHost)?

    private static var nextRequestID: Int32 = 1
    private static var pending: [Int32: (Bool, String) -> Void] = [:]

    /// Issues a request and registers its completion.
    public static func request(
        _ completion: @escaping (Bool, String) -> Void,
        _ body: (Int32) -> Void
    ) {
        let id = nextRequestID
        nextRequestID &+= 1
        pending[id] = completion
        body(id)
    }

    static func complete(requestID: Int32, ok: Bool, payload: String) {
        guard let completion = pending.removeValue(forKey: requestID) else { return }
        completion(ok, payload)
    }

    /// Host-initiated events, routed to whoever is listening.
    public static var onEvent: ((String, String) -> Void)?
}

/// In-process installation for compiled hosts whose implementation lives on
/// the other side of a native bridge (the Android app's Kotlin calls this,
/// exported through the generated bindings, before starting the runtime).
/// Hosts implemented in Swift call `SwiftFFI.installDependencies` directly;
/// the browser injects through the boot dependency dictionary.
@ExportedFunction(namespace: "convo")
public func installConvoHost(host: any ConvoHost) {
    installDependencies([
        ConvoDependencyKey.host: Lazy<any ConvoHost> { host }
    ])
}

/// The host calls this back when a request finishes.
@ExportedFunction(namespace: "convo")
public func convoRequestComplete(requestID: Int32, ok: Bool, payload: String) {
    ConvoServices.complete(requestID: requestID, ok: ok, payload: payload)
}

/// The host calls this for anything it initiates: "open" when a data channel
/// comes up, "frame" for an inbound frame, "answer" for a peer's reply arriving
/// over the same-origin channel, "state" for connection progress. For the
/// transport events ("open", "frame", "state") the payload begins with the
/// connection's peer id — "<peer>" or "<peer> <rest>" — so the guest can route
/// to the right conversation.
@ExportedFunction(namespace: "convo")
public func convoEvent(kind: String, payload: String) {
    ConvoServices.onEvent?(kind, payload)
}
