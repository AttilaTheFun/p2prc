import Crypto
import Foundation

/// Sealing for what a device keeps on disk: message logs, under a key
/// derived from the identity key, the one long-lived secret. A copy of the
/// store without the identity reads as noise.
///
/// The record is JSON (or any bytes) sealed with ChaCha20-Poly1305, carried
/// as base64 so every host store (UserDefaults, localStorage,
/// SharedPreferences) can hold it as a string.
public enum AtRest {
    /// The storage key for an identity: HKDF over the private key's raw
    /// bytes with a fixed label, so it is stable across launches and
    /// distinct from every MLS-derived secret.
    public static func key(identity: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: identity),
            info: Data("p2prc messages at rest".utf8), outputByteCount: 32
        )
    }

    public static func seal(_ plaintext: Data, key: SymmetricKey) throws -> String {
        try ChaChaPoly.seal(plaintext, using: key).combined.base64EncodedString()
    }

    public static func open(_ record: String, key: SymmetricKey) throws -> Data {
        guard let data = Data(base64Encoded: record) else { throw MLSError("at-rest record is not base64") }
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: data), using: key)
    }
}
