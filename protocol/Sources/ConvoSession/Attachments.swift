import ConvoCore
import Crypto
import Foundation

/// Sealing an attachment's bytes for the blob store: a fresh 256-bit key
/// per attachment, ChaCha20-Poly1305, the combined box (nonce ‖ ciphertext
/// ‖ tag) as the blob. The key travels only inside the sealed message.
public enum BlobSeal {
    public static func seal(_ plaintext: [UInt8]) throws -> (key: [UInt8], sealed: [UInt8]) {
        let key = SymmetricKey(size: .bits256)
        let box = try ChaChaPoly.seal(Data(plaintext), using: key)
        return (key.withUnsafeBytes { Array($0) }, Array(box.combined))
    }

    public static func open(_ sealed: [UInt8], key: [UInt8]) throws -> [UInt8] {
        let box = try ChaChaPoly.SealedBox(combined: Data(sealed))
        return Array(try ChaChaPoly.open(box, using: SymmetricKey(data: Data(key))))
    }

    /// The blob's name at the hosts: sha256 of the sealed bytes.
    public static func name(of sealed: [UInt8]) -> Hash32 { Hashing.sha256(sealed) }
}
