import Crypto
// FoundationEssentials has everything this file needs (Data, JSON, Date)
// without FoundationInternationalization — whose embedded ICU tables are
// ~33 MB of wasm data section. One plain `import Foundation` anywhere in the
// module graph pulls them back in.
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Smallest possible proof that swift-crypto's primitives work on this target,
/// including wasm: a hash, an HKDF expansion, and an X25519 agreement — the
/// three things MLS's key schedule is built from.
public enum CryptoProbe {
    public static func run() -> String {
        let digest = SHA256.hash(data: Array("p2prc".utf8))
        let hashHex = digest.hexString

        let secret = SymmetricKey(data: Array(repeating: UInt8(7), count: 32))
        let expanded = HKDF<SHA256>.expand(
            pseudoRandomKey: secret,
            info: Array("p2prc-mls-v1 test".utf8),
            outputByteCount: 32
        )
        let expandedHex = expanded.withUnsafeBytes { bytes in
            bytes.hexString
        }

        let a = Curve25519.KeyAgreement.PrivateKey()
        let b = Curve25519.KeyAgreement.PrivateKey()
        let ab = try! a.sharedSecretFromKeyAgreement(with: b.publicKey)
        let ba = try! b.sharedSecretFromKeyAgreement(with: a.publicKey)
        let agrees = ab == ba

        return "sha256=\(hashHex.prefix(16)) hkdf=\(expandedHex.prefix(16)) x25519_agrees=\(agrees)"
    }

    /// The same probe as a pass/fail, checked against a known answer rather
    /// than only against itself: `printf p2prc | shasum -a 256`. A backend that
    /// is merely self-consistent would pass a round-trip test and still be
    /// wrong; this catches that.
    public static var agrees: Bool {
        let hex = SHA256.hash(data: Array("p2prc".utf8))
            .hexString
        guard hex.hasPrefix("691146279f778b7d") else { return false }
        let a = Curve25519.KeyAgreement.PrivateKey()
        let b = Curve25519.KeyAgreement.PrivateKey()
        guard let ab = try? a.sharedSecretFromKeyAgreement(with: b.publicKey),
              let ba = try? b.sharedSecretFromKeyAgreement(with: a.publicKey)
        else { return false }
        return ab == ba
    }
}
