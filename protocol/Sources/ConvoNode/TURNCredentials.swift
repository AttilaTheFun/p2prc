import Crypto
import Foundation

/// Ephemeral TURN credentials in the "TURN REST API" shape every WebRTC stack
/// already understands (draft-uberti-behave-turn-rest): the username is
/// `<expiry>:<client id>` and the password is HMAC-SHA1(secret, username),
/// so the relay validates a credential from the secret alone, with no user
/// table and nothing to persist. A mailbox server mints them on request
/// (`/turn?for=<id>`); the relay checks them on Allocate.
///
/// The trust model matches the mailbox: anyone who can reach the server can
/// get a short-lived credential. What that buys an abuser is a few minutes
/// of relay bandwidth, capped by the server's allocation limits — the same
/// exposure any public TURN deployment has, and why lifetimes are short.
public struct TURNCredentials: Sendable {
    public let realm: String
    private let secret: [UInt8]

    public init(realm: String = "convo", secret: [UInt8]) {
        self.realm = realm
        self.secret = secret
    }

    public static func randomSecret() -> [UInt8] {
        (0..<32).map { _ in UInt8.random(in: 0...255) }
    }

    public struct Minted: Codable, Equatable, Sendable {
        public let username: String
        public let credential: String
        public let ttl: Int
    }

    /// A credential for `clientID` good for `ttl` seconds from `now`.
    public func mint(for clientID: String, ttl: Int = 3600, now: Date = Date()) -> Minted {
        let expiry = Int(now.timeIntervalSince1970) + ttl
        let username = "\(expiry):\(clientID)"
        return Minted(username: username, credential: password(for: username), ttl: ttl)
    }

    /// The password a valid, unexpired username implies, or nil.
    public func password(forValidUsername username: String, now: Date = Date()) -> String? {
        guard let colon = username.firstIndex(of: ":"),
              let expiry = Int(username[..<colon]),
              Double(expiry) > now.timeIntervalSince1970 else { return nil }
        return password(for: username)
    }

    private func password(for username: String) -> String {
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(username.utf8), using: SymmetricKey(data: secret))
        return Data(mac).base64EncodedString()
    }
}
