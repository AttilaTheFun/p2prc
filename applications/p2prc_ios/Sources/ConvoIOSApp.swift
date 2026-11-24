import CoreImage.CIFilterBuiltins
#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif
import ConvoApp
import ConvoUI
import ShakeKit
import SwiftUI
import UniformTypeIdentifiers
import UpdateKit
import ImageIO
#if canImport(UIKit)
import AVFoundation
#endif

/// The QR the host was asked to draw.
///
/// In a browser `drawQR` writes into the DOM beside the canvas; here the
/// native layer is SwiftUI, so the image is published and the app overlays it
/// — the same division of labour, one level up.
@MainActor
final class QRStore: ObservableObject {
    /// One store, shared by the host that draws into it and the view that
    /// shows it — they must observe the same object.
    static let shared = QRStore()

    #if canImport(UIKit)
    @Published var image: UIImage?
    #else
    @Published var image: CGImage?
    #endif

    /// The code as pixels. Nearest-neighbour scale, or the modules blur
    /// into unscannable grey.
    static func render(_ text: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "L"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        return CIContext().createCGImage(scaled, from: scaled.extent)
    }

    /// The code as a PNG in the temporary directory, for the UI's
    /// `AsyncImage`. One file per text (named by its hash), so a re-render
    /// of the same invite is a cache hit and a cancelled one leaves at most
    /// a few kilobytes behind until the system sweeps the directory.
    static func renderToFile(_ text: String) -> URL? {
        guard let cg = render(text) else { return nil }
        let name = "convo-qr-\(String(text.hashValue, radix: 36)).png"
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(name)
        guard let destination = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)
        else { return nil }
        CGImageDestinationAddImage(destination, cg, nil)
        guard CGImageDestinationFinalize(destination) else { return nil }
        return url
    }

    /// Kept for the share and save paths, which want the image in hand.
    func draw(_ text: String) {
        guard let cg = Self.render(text) else { return }
        #if canImport(UIKit)
        image = UIImage(cgImage: cg)
        #else
        image = cg
        #endif
    }

    func clear() { image = nil }

    /// The image as SwiftUI wants it. The platform types differ and the
    /// initializers differ with them, so the difference is resolved here
    /// rather than inside a ViewBuilder, where a `#if` would orphan every
    /// modifier chained after it.
    var swiftUIImage: Image? {
        guard let image else { return nil }
        #if canImport(UIKit)
        return Image(uiImage: image)
        #else
        return Image(image, scale: 1, label: Text("invite code"))
        #endif
    }

    /// The platform's share sheet, which is what "send this to someone" means
    /// on a phone. On a Mac there is no sheet without an anchor view to hang
    /// it off, and the useful thing to do with a link is paste it somewhere,
    /// so the pasteboard is the honest equivalent.
    #if canImport(UIKit)
    /// The controller a new presentation must hang off: the *topmost*
    /// presented controller, not the root. The pairing UI lives in a SwiftUI
    /// sheet, which is itself a presentation — presenting from the root while
    /// that sheet is up is silently refused by UIKit, which reads as a button
    /// that does nothing.
    static func topController() -> UIViewController? {
        guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene }).first,
            var top = scene.keyWindow?.rootViewController
        else { return nil }
        while let presented = top.presentedViewController { top = presented }
        return top
    }
    #endif

    func share(text: String) {
        #if canImport(UIKit)
        guard let root = Self.topController() else { return }
        let sheet = UIActivityViewController(activityItems: [text], applicationActivities: nil)
        // iPad requires an anchor or it raises rather than presenting.
        sheet.popoverPresentationController?.sourceView = root.view
        sheet.popoverPresentationController?.sourceRect = CGRect(
            x: root.view.bounds.midX, y: root.view.bounds.maxY - 80, width: 1, height: 1
        )
        root.present(sheet, animated: true)
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #endif
    }

    func copy(text: String) {
        #if canImport(UIKit)
        UIPasteboard.general.string = text
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #endif
    }

    /// A QR from a picture, decoded on-device with Vision. iOS offers the
    /// camera or the roll; macOS opens a file panel (Macs rarely have a
    /// useful rear camera, and a screenshot of the peer's code works fine).
    func scan(completion: @escaping (String?) -> Void) {
        #if canImport(UIKit)
        guard let root = Self.topController() else { return completion(nil) }
        // Straight into the camera, which closes itself on the first code
        // it reads. A device without a camera (the Simulator) picks a
        // picture instead, so the flow can still be exercised there.
        guard UIImagePickerController.isSourceTypeAvailable(.camera) else {
            let picker = UIImagePickerController()
            picker.sourceType = .photoLibrary
            let delegate = ScanDelegate { image in completion(image.flatMap(Self.decodeQR)) }
            picker.delegate = delegate
            objc_setAssociatedObject(picker, &ScanDelegate.key, delegate, .OBJC_ASSOCIATION_RETAIN)
            root.present(picker, animated: true)
            return
        }
        QRScannerController.present(from: root, completion: completion)
        #else
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.begin { response in
            guard response == .OK, let url = panel.url,
                  let image = CIImage(contentsOf: url)
            else { return completion(nil) }
            completion(Self.decode(image))
        }
        #endif
    }

    #if canImport(UIKit)
    private static func decodeQR(_ image: UIImage) -> String? {
        guard let ci = CIImage(image: image) else { return nil }
        return decode(ci)
    }
    #endif

    private static func decode(_ image: CIImage) -> String? {
        let detector = CIDetector(
            ofType: CIDetectorTypeQRCode, context: nil,
            options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
        )
        return detector?.features(in: image)
            .compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            .first
    }

    /// Photos on a phone; the Desktop on a Mac, which is where a screenshot
    /// would have gone anyway.
    func saveToPhotos() {
        guard let image else { return }
        #if canImport(UIKit)
        UIImageWriteToSavedPhotosAlbum(image, nil, nil, nil)
        #else
        let bitmap = NSBitmapImageRep(cgImage: image)
        guard let png = bitmap.representation(using: .png, properties: [:]) else { return }
        let desktop = FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
        guard let url = desktop?.appendingPathComponent("convo-invite.png") else { return }
        try? png.write(to: url)
        #endif
    }
}

#if canImport(UIKit)
/// Bridges UIImagePickerController's delegate callbacks to a closure.
private final class ScanDelegate: NSObject, UIImagePickerControllerDelegate, UINavigationControllerDelegate {
    static var key: UInt8 = 0
    private let completion: (UIImage?) -> Void

    init(completion: @escaping (UIImage?) -> Void) {
        self.completion = completion
    }

    func imagePickerController(
        _ picker: UIImagePickerController,
        didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]
    ) {
        picker.dismiss(animated: true)
        completion(info[.originalImage] as? UIImage)
    }

    func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
        picker.dismiss(animated: true)
        completion(nil)
    }
}
#endif

#if os(iOS)
/// Convo on iOS: compiled native Swift, real SwiftUI.
///
/// No wasm on device — the client (`ConvoApp` module) runs as ordinary Swift
/// in this process, the networking stack is injected in-process, and the UI
/// (`ConvoUI`) is the same source the web renders through wasm. Real SwiftUI
/// means the OS drives dark mode; nothing here manages the colour scheme.
@main
struct ConvoiOSApp: App {
    init() {
        // Install the host before any view asks the client for anything.
        let host = NativeNetwork(qr: QRStore.shared)
        ConvoNativeHost.install(host: host)
        VideoCallPresenter.shared.install(host: host)
        DebugPairing.installIfRequested()
        // The build this is, told to Applications (in the team's own builds;
        // without the app group it does nothing).
        AppUpdates.start()
    }

    var body: some Scene {
        WindowGroup {
            // Shake to report a bug, as an issue in P2PRC's repository.
            ChatScreen()
                .shakeToReport(repository: "AttilaTheFun/p2prc")
                // p2prc:// (Applications' Open, an invite or handoff link).
                .onOpenURL { Client.shared.open(url: $0.absoluteString) }
        }
    }
}
#endif

/// `CONVO_DEBUG_PAIRING=1` (a simulator launched with
/// `SIMCTL_CHILD_CONVO_DEBUG_PAIRING=1`): a hands-free presenter for
/// end-to-end tests, the iOS twin of the Mac app's hook. It invites on
/// launch, names the new contact, opens the conversation, and prints every
/// transition to stdout — the pairing code included, which is why this must
/// never be on outside a test. A simulator cannot be tapped from a shell, so
/// this stream is the automation surface.
@MainActor
enum DebugPairing {
    private static var timer: Timer?

    static func installIfRequested() {
        guard ProcessInfo.processInfo.environment["CONVO_DEBUG_PAIRING"] == "1" else { return }
        setbuf(stdout, nil)
        let client = Client.shared
        print("DEBUG pairing hook armed")
        // One observer over the client: each value printed when it changes,
        // the conversations on every change.
        var seenPhase: Client.Phase? = nil
        var seenStatus = "", seenNaming: String? = nil
        let report: () -> Void = {
            if client.phase != seenPhase {
                seenPhase = client.phase
                print("DEBUG phase: \(client.phase)")
                // A test run creates its identity by itself, as the Mac's hook does.
                if client.phase == .needsIdentity { DispatchQueue.main.async { _ = client.createIdentity(); print("DEBUG identity created") } }
            }
            if client.status != seenStatus {
                seenStatus = client.status
                if !seenStatus.isEmpty { print("DEBUG status: \(seenStatus)") }
            }
            if client.pendingNaming != seenNaming {
                seenNaming = client.pendingNaming
                if let naming = seenNaming {
                    print("DEBUG naming: \(naming) -> Droid")
                    DispatchQueue.main.async {
                        client.renameContact(naming, to: "Droid")
                        client.debugOpenContact = naming
                    }
                }
            }
            for convo in client.conversations {
                print("DEBUG conv \(convo.id.prefix(8)) connected=\(convo.connected) call=\(convo.callState) msgs=\(convo.messages.count)")
            }
        }
        client.observe(report)
        report()
        // Open an existing conversation if no pairing names a new one, so a
        // screenshot of the chat page needs no taps. (Fall back to opening
        // whatever conversation is first.)
        // CONVO_DEBUG_DETAILS=1 also raises the contact's details, for a
        // screenshot of the pane where nothing can be tapped.
        if ProcessInfo.processInfo.environment["CONVO_DEBUG_DETAILS"] == "1" {
            DispatchQueue.main.asyncAfter(deadline: .now() + 7) { client.setDetails(true) }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
            if client.debugOpenContact == nil, let first = client.conversations.first {
                client.debugOpenContact = first.contactID
            }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
            MainActor.assumeIsolated {
                if client.inviteLink.isEmpty, client.phase == .idle {
                    print("DEBUG inviting")
                    client.invite()
                }
                if !client.inviteLink.isEmpty {
                    // As the Mac's hook does: the link a test hands the other client.
                    print("DEBUG inviteLink: \(client.inviteLink)")
                    timer?.invalidate()
                }
            }
        }
    }
}

#if canImport(UIKit)
/// A full-screen live camera that reads QR codes as they come into view
/// (AVFoundation's metadata output, decoded on the device) and dismisses
/// itself with the first one; Cancel dismisses with nothing.
final class QRScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var completion: ((String?) -> Void)?

    static func present(from root: UIViewController, completion: @escaping (String?) -> Void) {
        func show() {
            let scanner = QRScannerController()
            scanner.completion = completion
            scanner.modalPresentationStyle = .fullScreen
            root.present(scanner, animated: true)
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            show()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async { granted ? show() : completion(nil) }
            }
        default:
            let alert = UIAlertController(title: "Camera access is off",
                                          message: "Allow P2PRC to use the camera in Settings to scan a pairing code.",
                                          preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Open Settings", style: .default) { _ in
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                completion(nil)
            })
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completion(nil) })
            root.present(alert, animated: true)
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        if let camera = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: camera),
           session.canAddInput(input) {
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            if session.canAddOutput(output) {
                session.addOutput(output)
                output.setMetadataObjectsDelegate(self, queue: .main)
                output.metadataObjectTypes = [.qr]
            }
        }
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(layer)
        preview = layer

        // A square frame to aim with, and a hint under it.
        let frame = UIView()
        frame.layer.borderColor = UIColor.white.cgColor
        frame.layer.borderWidth = 3
        frame.layer.cornerRadius = 20
        frame.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(frame)
        let hint = UILabel()
        hint.text = "Point the camera at a pairing code"
        hint.textColor = .white
        hint.font = .preferredFont(forTextStyle: .headline)
        hint.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(hint)
        var cancelConfig = UIButton.Configuration.filled()
        cancelConfig.image = UIImage(systemName: "xmark")
        cancelConfig.cornerStyle = .capsule
        cancelConfig.baseBackgroundColor = UIColor(white: 0, alpha: 0.5)
        cancelConfig.baseForegroundColor = .white
        let cancel = UIButton(configuration: cancelConfig, primaryAction: UIAction { [weak self] _ in self?.finish(nil) })
        cancel.accessibilityLabel = "Cancel"
        cancel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(cancel)
        NSLayoutConstraint.activate([
            frame.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            frame.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            frame.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.7),
            frame.heightAnchor.constraint(equalTo: frame.widthAnchor),
            hint.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            hint.topAnchor.constraint(equalTo: frame.bottomAnchor, constant: 24),
            cancel.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 16),
            cancel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            cancel.widthAnchor.constraint(equalToConstant: 44),
            cancel.heightAnchor.constraint(equalToConstant: 44),
        ])
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        let session = session
        DispatchQueue.global(qos: .userInitiated).async { session.stopRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard completion != nil,
              let code = metadataObjects.compactMap({ ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue }).first
        else { return }
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        finish(code)
    }

    private func finish(_ code: String?) {
        guard let completion else { return }
        self.completion = nil
        dismiss(animated: true) { completion(code) }
    }
}
#endif
