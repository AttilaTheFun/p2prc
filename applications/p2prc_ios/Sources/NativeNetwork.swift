import Communication
import ConvoCalling
import CommunicationWebRTC
import Foundation
import ImageIO
import Security
import UniformTypeIdentifiers
#if canImport(PhotosUI)
import PhotosUI
#endif
import ConvoNet
import ConvoServices

/// The native networking stack under the shared client: WebRTC from the
/// Communication package, HTTP from URLSession, and honest answers about
/// what the platform can do (it can scan a QR).
///
/// Everything here is mechanical. It moves bytes and answers requests. It
/// makes no decisions about which signaling server to trust or when to fall
/// back to a public STUN server — all of that is in the client above it,
/// identical to the browser's, so both behave the same way for the same
/// reasons.
///
/// Compiled, not wasm: the native apps run the client as ordinary Swift in
/// this same process, so completions and events are direct calls to the
/// `@ExportedFunction`s rather than trips across a wasm boundary. The client
/// is an `ObservableObject`, so mutating its state repaints the view — no
/// manual render pump.
@MainActor
final class NativeNetwork: ConvoHost {
    private var webRTC: NativeWebRTC?
    private let qr: QRStore

    init(qr: QRStore) {
        self.qr = qr
    }

    // MARK: - Completions

    private func complete(_ requestID: Int32, _ ok: Bool, _ payload: String) {
        guard requestID != 0 else { return }
        convoRequestComplete(requestID: requestID, ok: ok, payload: payload)
    }

    /// Host-initiated events: the channel opening, a frame arriving, a signal
    /// or announcement landing. A direct call into the client, which then
    /// mutates its published state and SwiftUI redraws.
    private func emit(_ kind: String, _ payload: String) {
        convoEvent(kind: kind, payload: payload)
    }

    // MARK: - Capabilities

    func capabilities(requestID p0: Int32) {
        complete(p0, true, #"{"scansQR":true,"picksImages":true}"#)
    }

    /// The seed signaling servers, from the app's Info.plist (`ConvoSeeds`,
    /// an array of URLs): configuration, not code.
    func seeds(requestID p0: Int32) {
        // CONVO_SEEDS in the environment overrides the bundle's list — for
        // pointing a test build at a local server.
        if let override = ProcessInfo.processInfo.environment["CONVO_SEEDS"], !override.isEmpty {
            complete(p0, true, override)
            return
        }
        let list = Bundle.main.object(forInfoDictionaryKey: "ConvoSeeds") as? [String] ?? []
        complete(p0, true, list.joined(separator: ","))
    }

    // MARK: - Mechanical networking

    func httpGet(requestID p0: Int32, url p1: String) {
        guard let target = URL(string: p1) else {
            complete(p0, false, "")
            return
        }
        Task {
            do {
                var request = URLRequest(url: target)
                request.timeoutInterval = 8
                let (data, response) = try await URLSession.shared.data(for: request)
                let ok = (response as? HTTPURLResponse).map { (200..<300).contains($0.statusCode) } ?? false
                await MainActor.run {
                    self.complete(p0, ok, ok ? String(decoding: data, as: UTF8.self) : "")
                }
            } catch {
                await MainActor.run { self.complete(p0, false, "") }
            }
        }
    }

    func httpPost(requestID p0: Int32, url p1: String, body p2: String) {
        guard let target = URL(string: p1) else {
            complete(p0, false, "")
            return
        }
        Task {
            do {
                var request = URLRequest(url: target)
                request.httpMethod = "POST"
                request.timeoutInterval = 8
                request.setValue(p2.hasPrefix("{") ? "application/json" : "text/plain", forHTTPHeaderField: "Content-Type")
                request.httpBody = Data(p2.utf8)
                let (data, response) = try await URLSession.shared.data(for: request)
                let ok = (response as? HTTPURLResponse).map { (200..<300).contains($0.statusCode) } ?? false
                await MainActor.run {
                    self.complete(p0, ok, ok ? String(decoding: data, as: UTF8.self) : "")
                }
            } catch {
                await MainActor.run { self.complete(p0, false, "") }
            }
        }
    }

    // MARK: - Pictures

    #if canImport(UIKit)
    private var pickerDelegate: AnyObject?

    private static func topViewController() -> UIViewController? {
        guard let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first,
              var top = scene.keyWindow?.rootViewController else { return nil }
        while let presented = top.presentedViewController { top = presented }
        return top
    }

    private final class PickerDelegate: NSObject, PHPickerViewControllerDelegate {
        let finish: (Data?) -> Void
        init(finish: @escaping (Data?) -> Void) { self.finish = finish }
        func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
            picker.dismiss(animated: true)
            guard let provider = results.first?.itemProvider else { return finish(nil) }
            provider.loadDataRepresentation(forTypeIdentifier: UTType.image.identifier) { data, _ in
                DispatchQueue.main.async { self.finish(data) }
            }
        }
    }
    #endif

    func pickImage(requestID p0: Int32) {
        #if canImport(AppKit)
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        panel.begin { [weak self] result in
            guard result == .OK, let url = panel.url, let data = try? Data(contentsOf: url), let encoded = Self.downscaled(data) else {
                self?.complete(p0, false, ""); return
            }
            self?.complete(p0, true, encoded)
        }
        #else
        var configuration = PHPickerConfiguration()
        configuration.filter = .images
        configuration.selectionLimit = 1
        let picker = PHPickerViewController(configuration: configuration)
        let delegate = PickerDelegate { [weak self] data in
            self?.pickerDelegate = nil
            guard let data, let encoded = Self.downscaled(data) else { self?.complete(p0, false, ""); return }
            self?.complete(p0, true, encoded)
        }
        pickerDelegate = delegate
        picker.delegate = delegate
        guard let top = Self.topViewController() else { return complete(p0, false, "") }
        top.present(picker, animated: true)
        #endif
    }

    /// At most 1600px on the long side, oriented, as JPEG: what a message
    /// carries, whatever the camera produced.
    static func downscaled(_ data: Data, maxPixels: CGFloat = 1600) -> String? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        let options: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                        kCGImageSourceThumbnailMaxPixelSize: maxPixels,
                                        kCGImageSourceCreateThumbnailWithTransform: true]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else { return nil }
        let out = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(destination, image, [kCGImageDestinationLossyCompressionQuality: 0.82] as CFDictionary)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return "image/jpeg|\(image.width)|\(image.height)|" + (out as Data).base64EncodedString()
    }

    func imageURL(requestID p0: Int32, key p1: String, bytes64 p2: String, mime p3: String) {
        guard let data = Data(base64Encoded: p2) else { return complete(p0, false, "") }
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("convo-img-\(p1).\(p3 == "image/png" ? "png" : "jpg")")
        if !FileManager.default.fileExists(atPath: url.path) {
            do { try data.write(to: url, options: .atomic) } catch { return complete(p0, false, "") }
        }
        complete(p0, true, url.absoluteString)
    }

    func httpGetBytesSigned(requestID p0: Int32, url p1: String, auth p2: String) {
        getBytes(requestID: p0, url: p1, headers: ["X-Convo-Auth": p2])
    }

    func httpGetBytes(requestID p0: Int32, url p1: String) { getBytes(requestID: p0, url: p1, headers: [:]) }

    private func getBytes(requestID p0: Int32, url p1: String, headers: [String: String]) {
        guard let target = URL(string: p1) else { complete(p0, false, ""); return }
        Task {
            do {
                var request = URLRequest(url: target)
                request.timeoutInterval = 8
                for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
                let (data, response) = try await URLSession.shared.data(for: request)
                let ok = (response as? HTTPURLResponse).map { (200..<300).contains($0.statusCode) } ?? false
                await MainActor.run { self.complete(p0, ok, ok ? data.base64EncodedString() : "") }
            } catch {
                await MainActor.run { self.complete(p0, false, "") }
            }
        }
    }

    func httpPostBytes(requestID p0: Int32, url p1: String, body64 p2: String) {
        guard let target = URL(string: p1), let body = Data(base64Encoded: p2) else { complete(p0, false, ""); return }
        Task {
            do {
                var request = URLRequest(url: target)
                request.httpMethod = "POST"
                request.timeoutInterval = 8
                request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
                request.httpBody = body
                let (data, response) = try await URLSession.shared.data(for: request)
                let ok = (response as? HTTPURLResponse).map { (200..<300).contains($0.statusCode) } ?? false
                await MainActor.run { self.complete(p0, ok, ok ? data.base64EncodedString() : "") }
            } catch {
                await MainActor.run { self.complete(p0, false, "") }
            }
        }
    }

    func delay(requestID p0: Int32, ms p1: Int32) {
        Task {
            try? await Task.sleep(nanoseconds: UInt64(max(0, p1)) * 1_000_000)
            await MainActor.run { self.complete(p0, true, "") }
        }
    }

    // MARK: - Transport the guest drives
    //
    // The browser gets WebRTC from the platform; here it comes from the
    // Communication package. The guest cannot tell the difference, which is
    // the point: the same wasm drives pairing on both, and the blobs are
    // byte-compatible so a phone and a tab pair with each other.

    private func rtc() -> NativeWebRTC {
        if let webRTC { return webRTC }
        let made = NativeWebRTC(
            onOpen: { [weak self] peer in
                Task { @MainActor in
                    self?.qr.clear()
                    self?.emit("open", peer)
                }
            },
            onFrame: { [weak self] peer, text in
                Task { @MainActor in self?.emit("frame", peer + " " + text) }
            },
            onState: { [weak self] peer, state in
                Task { @MainActor in self?.emit("state", peer + " " + state) }
            }
        )
        webRTC = made
        return made
    }

    func createOffer(requestID p0: Int32, peer p1: String) {
        let rtc = rtc()
        Task {
            do {
                let blob = try await rtc.createOffer(peer: p1)
                await MainActor.run { self.complete(p0, true, blob) }
            } catch {
                await MainActor.run { self.complete(p0, false, "\(error)") }
            }
        }
    }

    func acceptOffer(requestID p0: Int32, peer p1: String, blob p2: String) {
        let rtc = rtc()
        Task {
            do {
                let answer = try await rtc.acceptOffer(peer: p1, blob: p2)
                await MainActor.run { self.complete(p0, true, answer) }
            } catch {
                await MainActor.run { self.complete(p0, false, "\(error)") }
            }
        }
    }

    func acceptAnswer(requestID p0: Int32, peer p1: String, blob p2: String) {
        let rtc = rtc()
        Task {
            try? await rtc.acceptAnswer(peer: p1, blob: p2)
        }
    }

    func sendFrame(peer p0: String, text p1: String) {
        guard let bytes = Data(base64Encoded: p1) else { return }
        let rtc = rtc()
        Task { await rtc.send(peer: p0, bytes: bytes) }
    }

    func closeConnection(peer p0: String) {
        let rtc = rtc()
        Task { await rtc.close(peer: p0) }
    }

    /// Same-origin answer relay is a browser affordance (BroadcastChannel);
    /// on a phone the reply travels as a link or a scanned code instead.

    // MARK: - Platform odds and ends

    /// Where the client's state lives. `CONVO_DATA_SUITE` in the environment
    /// moves it to a separate suite, so a debug/test run (the hands-free
    /// pairing harness) has its own identity and contacts and never
    /// touches the person's real ones. P2PRC starts fresh: an identity from
    /// an earlier app (Convo) comes over by its recovery phrase or the
    /// device handoff, not from that app's storage.
    private static let defaults: UserDefaults = {
        if let suite = ProcessInfo.processInfo.environment["CONVO_DATA_SUITE"], !suite.isEmpty,
           let separate = UserDefaults(suiteName: "com.LoganShire.P2PRC." + suite) {
            return separate
        }
        return .standard
    }()

    func save(key p0: String, value p1: String) {
        Self.defaults.set(p1, forKey: "p2prc:" + p0)
    }

    func load(requestID p0: Int32, key p1: String) {
        complete(p0, true, Self.defaults.string(forKey: "p2prc:" + p1) ?? "")
    }

    /// Secrets go to the keychain, scoped like the defaults suite so a
    /// test suite never sees the person's identity.
    /// Its own service, not an earlier app's ("com.LoganShire.P2PRC" was a
    /// much older build's, whose items it must not pick up).
    private static let keychainService: String = {
        let suite = ProcessInfo.processInfo.environment["CONVO_DATA_SUITE"] ?? ""
        return "org.p2prc.app" + (suite.isEmpty ? "" : "." + suite)
    }()

    #if os(macOS)
    /// Whether this binary carries an Apple-issued signature (Developer ID,
    /// the Mac App Store, a development team). A local bazel build is only
    /// ad-hoc signed, and the keychain treats every rebuild of it as a new
    /// program: each launch asks for permission again. Such a build keeps
    /// its secrets in its defaults suite; a distributed build (.dmg, App
    /// Store) uses the keychain.
    static let signedForDistribution: Bool = {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess, let code else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement) == errSecSuccess, let requirement else { return false }
        return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
    }()
    private static let secretsBypassKeychain = ProcessInfo.processInfo.environment["CONVO_DEBUG_PAIRING"] == "1" || !signedForDistribution
    #else
    /// The hands-free test harness (CONVO_DEBUG_PAIRING) keeps its
    /// throwaway suite's secrets out of the keychain: every rebuilt binary
    /// would otherwise stop on the keychain's access prompt.
    private static let secretsBypassKeychain = ProcessInfo.processInfo.environment["CONVO_DEBUG_PAIRING"] == "1"
    #endif

    func saveSecret(key p0: String, value p1: String) {
        if Self.secretsBypassKeychain {
            // The defaults suite (the test harness's, or the unsigned Mac
            // build's); the file store of earlier builds is cleared.
            try? FileManager.default.removeItem(at: Self.secretFile(p0, service: Self.keychainService))
            if p1.isEmpty { Self.defaults.removeObject(forKey: "secret:" + p0) } else { Self.defaults.set(p1, forKey: "secret:" + p0) }
            return
        }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.keychainService, kSecAttrAccount as String: p0]
        SecItemDelete(query as CFDictionary)
        try? FileManager.default.removeItem(at: Self.secretFile(p0, service: Self.keychainService))
        guard !p1.isEmpty else { return }
        var add = query
        add[kSecValueData as String] = Data(p1.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status != errSecSuccess else { return }
        // The keychain refused (a locked keychain, a session without one, a
        // denied access prompt): the secret still has to outlive this
        // launch, or the next one is a stranger to every conversation. A
        // private file in the app's own support directory is the fallback.
        NSLog("convo: keychain save of %@ failed (%d); keeping it in the app's support directory", p0, status)
        let url = Self.secretFile(p0, service: Self.keychainService)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? Data(p1.utf8).write(to: url, options: [.atomic, .completeFileProtection])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    func loadSecret(requestID p0: Int32, key p1: String) {
        if Self.secretsBypassKeychain {
            if let value = Self.defaults.string(forKey: "secret:" + p1) { return complete(p0, true, value) }
            // A secret the keychain refused was kept in a file: read it and
            // move it over. The keychain is never asked here: its access
            // prompt is the thing this storage exists to avoid.
            let kept = (try? Data(contentsOf: Self.secretFile(p1, service: Self.keychainService))).map { String(decoding: $0, as: UTF8.self) }
            if let kept, !kept.isEmpty { saveSecret(key: p1, value: kept) }
            return complete(p0, true, kept ?? "")
        }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.keychainService, kSecAttrAccount as String: p1,
                                    kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess { return complete(p0, true, String(decoding: (result as? Data) ?? Data(), as: UTF8.self)) }
        if status != errSecItemNotFound { NSLog("convo: keychain load of %@ failed (%d)", p1, status) }
        if let data = try? Data(contentsOf: Self.secretFile(p1, service: Self.keychainService)) { return complete(p0, true, String(decoding: data, as: UTF8.self)) }
        complete(p0, true, "")
    }

    private static func secretFile(_ key: String, service: String) -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent(service, isDirectory: true).appendingPathComponent("secrets", isDirectory: true).appendingPathComponent(key)
    }

    func pageURL(requestID p0: Int32) { complete(p0, true, "") }
    func openingHash(requestID p0: Int32) { complete(p0, true, "") }
    func setHash(value p0: String) {}
    func drawQR(elementID p0: String, text p1: String) {
        if p1.isEmpty { qr.clear() } else { qr.draw(p1) }
    }

    /// The code as a temporary PNG the UI's `AsyncImage` loads by file URL.
    func qrImage(requestID p0: Int32, text p1: String) {
        guard let url = QRStore.renderToFile(p1) else { return complete(p0, false, "") }
        complete(p0, true, url.absoluteString)
    }

    func share(text p0: String) { qr.share(text: p0) }
    func copyText(text p0: String) { qr.copy(text: p0) }

    func saveQR(elementID p0: String) { qr.saveToPhotos() }

    func setIceServers(json p0: String) {
        // Stored for the next connection; the Communication configuration
        // takes its ICE list at creation time. Entries carry credentials
        // for TURN, nothing for STUN.
        struct Entry: Decodable {
            let urls: [String]
            let username: String?
            let credential: String?
        }
        if let data = p0.data(using: .utf8),
           let entries = try? JSONDecoder().decode([Entry].self, from: data) {
            let servers = entries.map { entry -> CommunicationICEServer in
                if let username = entry.username, let credential = entry.credential {
                    return .turn(entry.urls, username: username, credential: credential)
                }
                return .stun(entry.urls)
            }
            let rtc = webRTC
            Task { await rtc?.setIceServers(servers) }
        }
    }

    // Calls: audio on the same peer connection as the chat, added and
    // removed mid-connection (Communication.addLocalAudio/removeLocalAudio).
    func callStart(requestID p0: Int32, peer p1: String, video p2: Bool) {
        let rtc = rtc()
        Task {
            do {
                let sdp = try await rtc.callStart(peer: p1, video: p2)
                await MainActor.run { self.complete(p0, true, sdp) }
            } catch {
                // The reason goes back as the payload, for the chat's note.
                await MainActor.run { self.complete(p0, false, String(describing: error)) }
            }
        }
    }

    func callApplyRemote(requestID p0: Int32, peer p1: String, sdp p2: String, isOffer p3: Bool, video p4: Bool) {
        let rtc = rtc()
        Task {
            do {
                let answer = try await rtc.callApplyRemote(peer: p1, sdp: p2, isOffer: p3, video: p4)
                await MainActor.run { self.complete(p0, true, answer) }
            } catch {
                // The reason goes back as the payload, for the chat's note.
                await MainActor.run { self.complete(p0, false, String(describing: error)) }
            }
        }
    }

    func callEnd(peer p0: String) {
        let rtc = rtc()
        Task { await rtc.callEnd(peer: p0) }
    }

    /// The live connection for a peer, for the video call's views.
    func videoConnection(peer: String) async -> CallSession? {
        try? await rtc().callMedia(peer: peer)
    }

    func scanQR(requestID p0: Int32) {
        qr.scan { [weak self] decoded in
            Task { @MainActor in self?.complete(p0, decoded != nil, decoded ?? "") }
        }
    }
}

