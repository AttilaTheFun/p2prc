import CryptoKit
// FoundationEssentials has everything this file needs (Data, JSON, Date)
// without FoundationInternationalization — whose embedded ICU tables are
// ~33 MB of wasm data section. One plain `import Foundation` anywhere in the
// module graph pulls them back in.
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A versioned, Ed25519-signed copy of the Convo web app.
///
/// Hosts adopt a bundle only when its version is higher than the one they are
/// serving *and* its signature verifies against the project's public key, so
/// clients can carry updates from host to host without anyone being able to
/// inject their own code.
public struct SignedBundle: Sendable {
    public var version: Int
    /// Relative file name -> contents (e.g. "index.html").
    public var files: [String: Data]
    /// Ed25519 signature over `canonicalPayload`.
    public var signature: Data

    public init(version: Int, files: [String: Data], signature: Data) {
        self.version = version
        self.files = files
        self.signature = signature
    }

    /// The exact bytes that get signed: the version plus every file's name and
    /// SHA-256, in sorted order. Deterministic across machines and languages,
    /// and small regardless of bundle size.
    public static func canonicalPayload(version: Int, files: [String: Data]) -> Data {
        var text = "convo-bundle-v1\nversion:\(version)\n"
        for name in files.keys.sorted() {
            let digest = SHA256.hash(data: files[name] ?? Data())
            let hex = digest.map { String(format: "%02x", $0) }.joined()
            text += "\(name):\(hex)\n"
        }
        return Data(text.utf8)
    }

    public var canonicalPayload: Data {
        Self.canonicalPayload(version: version, files: files)
    }

    public func isValid(publicKey: Curve25519.Signing.PublicKey) -> Bool {
        publicKey.isValidSignature(signature, for: canonicalPayload)
    }

    // MARK: - Wire format

    /// JSON envelope used to move a bundle between a host and a browser:
    /// `{version, signature (base64), files: {name: base64}}`.
    public func jsonObject() -> [String: Any] {
        var encoded: [String: String] = [:]
        for (name, data) in files {
            encoded[name] = data.base64EncodedString()
        }
        return [
            "version": version,
            "signature": signature.base64EncodedString(),
            "files": encoded,
        ]
    }

    public init?(jsonObject: Any?) {
        guard let json = jsonObject as? [String: Any],
              let version = json["version"] as? Int,
              let signatureText = json["signature"] as? String,
              let signature = Data(base64Encoded: signatureText),
              let encodedFiles = json["files"] as? [String: String]
        else { return nil }
        var files: [String: Data] = [:]
        for (name, text) in encodedFiles {
            // Reject path traversal and nesting: bundles are a flat file list.
            guard !name.contains("/"), !name.contains(".."), let data = Data(base64Encoded: text) else {
                return nil
            }
            files[name] = data
        }
        guard !files.isEmpty else { return nil }
        self.init(version: version, files: files, signature: signature)
    }

    // MARK: - Disk

    public static let signatureFileName = "bundle-signature.json"

    /// Loads the site files in `directory` plus the sidecar signature file.
    /// `signatureDirectory` defaults to `directory`.
    public static func load(directory: String, signatureDirectory: String? = nil) -> SignedBundle? {
        let signatureDir = signatureDirectory ?? directory
        guard let signatureData = FileManager.default.contents(atPath: signatureDir + "/" + signatureFileName),
              let json = try? JSONSerialization.jsonObject(with: signatureData) as? [String: Any],
              let version = json["version"] as? Int,
              let signatureText = json["signature"] as? String,
              let signature = Data(base64Encoded: signatureText),
              let enumerator = FileManager.default.enumerator(atPath: directory)
        else { return nil }

        // Recursive: runtime/ and assets/ hold the JS runtime and the wasm
        // module, so a top-level-only walk would verify almost nothing.
        var files: [String: Data] = [:]
        for case let relative as String in enumerator {
            let name = (relative as NSString).lastPathComponent
            if name.hasPrefix(".") || relative == signatureFileName { continue }
            var isDirectory: ObjCBool = false
            let path = directory + "/" + relative
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
                  !isDirectory.boolValue,
                  let data = FileManager.default.contents(atPath: path) else { continue }
            files[relative] = data
        }
        guard !files.isEmpty else { return nil }
        return SignedBundle(version: version, files: files, signature: signature)
    }

    /// Writes the files and the sidecar signature into `directory`.
    public func write(to directory: String) throws {
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        for (name, data) in files {
            try data.write(to: URL(fileURLWithPath: directory + "/" + name), options: .atomic)
        }
        let json: [String: Any] = ["version": version, "signature": signature.base64EncodedString()]
        let data = try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: URL(fileURLWithPath: directory + "/" + Self.signatureFileName), options: .atomic)
    }
}

public enum ConvoKeys {
    /// The project's signing public key (base64 raw Ed25519). The matching
    /// private key lives outside the repository — see tools/convo_sign.
    public static let publicKeyBase64 = "V/a0p/mRfwhQVDX4QMFNnPZ6TipYo3EtJBjQxCA/QKs="

    public static func publicKey(overrideBase64: String? = nil) -> Curve25519.Signing.PublicKey? {
        let text = overrideBase64 ?? publicKeyBase64
        guard let raw = Data(base64Encoded: text),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
        else { return nil }
        return key
    }
}
