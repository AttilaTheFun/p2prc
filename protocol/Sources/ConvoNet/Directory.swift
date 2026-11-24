#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import ConvoFoundation
#endif

/// What the host's networking stack can do — the only thing that differs
/// between a browser tab and a native client, asked once at startup so the
/// shared UI can show or hide what the platform supports.
public struct NetworkCapabilities: Encodable, Equatable, Sendable {
    /// Can decode a QR code from the camera or a picture (a native app);
    /// a browser tab pairs by opening the link instead.
    public let scansQR: Bool
    /// Can offer a picture to send (a photo picker, a file chooser).
    public let picksImages: Bool

    public init(scansQR: Bool, picksImages: Bool = false) { self.scansQR = scansQR; self.picksImages = picksImages }

    /// A browser tab.
    public static let browser = NetworkCapabilities(scansQR: false)
}

/// Hosts older than a field answer without it; it reads as false.
extension NetworkCapabilities: Decodable {
    private enum CodingKeys: String, CodingKey { case scansQR, picksImages }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(scansQR: try c.decodeIfPresent(Bool.self, forKey: .scansQR) ?? false,
                  picksImages: try c.decodeIfPresent(Bool.self, forKey: .picksImages) ?? false)
    }
}


/// One entry of the ICE server list a client hands its WebRTC stack —
/// the RFC shape every stack takes natively.
