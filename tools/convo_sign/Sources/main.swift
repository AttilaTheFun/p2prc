import CryptoKit
import Foundation
import ConvoBundle

let usage = """
convo_sign — sign Convo app bundles so hosts will accept them as updates

USAGE:
  convo_sign keygen [--key <path>] [--force]
      Create an Ed25519 signing key. Prints the public key to paste into
      libraries/convo_bundle/Sources/SignedBundle.swift.

  convo_sign sign --site-dir <path> [--version <n>] [--key <path>]
      Sign the site files, writing bundle-signature.json next to them.
      Without --version, bumps the existing version by one.

  convo_sign verify --site-dir <path>
      Check the current signature against the built-in public key.

The private key defaults to ~/.p2prc/signing-key (the key the site already trusts) and must never be committed.
"""

func realHome() -> String {
    if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir {
        return String(cString: dir)
    }
    return NSHomeDirectory()
}

var arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    print(usage)
    exit(0)
}
arguments.removeFirst()

var keyPath = realHome() + "/.p2prc/signing-key"   // the key the published site verifies against; unchanged by the rename
var siteDir: String?
var version: Int?
var force = false

while !arguments.isEmpty {
    let flag = arguments.removeFirst()
    switch flag {
    case "--key":
        keyPath = arguments.removeFirst()
    case "--site-dir":
        siteDir = arguments.removeFirst()
    case "--version":
        version = Int(arguments.removeFirst())
    case "--force":
        force = true
    case "-h", "--help":
        print(usage)
        exit(0)
    default:
        FileHandle.standardError.write(Data("error: unknown option \(flag)\n".utf8))
        exit(2)
    }
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(1)
}

func loadPrivateKey() -> Curve25519.Signing.PrivateKey {
    guard let text = try? String(contentsOfFile: keyPath, encoding: .utf8),
          let raw = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)),
          let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    else {
        fail("could not read a signing key at \(keyPath) — run `convo_sign keygen` first")
    }
    return key
}

/// Every file under `directory`, keyed by its path relative to it.
///
/// Recursive: the site has `runtime/` and `assets/` subdirectories, and a
/// signature that covered only the top level would leave the JS runtime and
/// the wasm module unsigned — which is most of what actually executes.
func walk(_ directory: String) -> [String: Data] {
    let manager = FileManager.default
    guard let enumerator = manager.enumerator(atPath: directory) else { return [:] }
    var files: [String: Data] = [:]
    for case let relative as String in enumerator {
        let name = (relative as NSString).lastPathComponent
        if name.hasPrefix(".") || relative == SignedBundle.signatureFileName { continue }
        var isDirectory: ObjCBool = false
        let path = directory + "/" + relative
        guard manager.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue,
              let data = manager.contents(atPath: path)
        else { continue }
        files[relative] = data
    }
    return files
}

func loadFiles(_ directory: String) -> [String: Data] {
    let files = walk(directory)
    guard !files.isEmpty else { fail("no files found in \(directory)") }
    return files
}

switch command {
case "keygen":
    if FileManager.default.fileExists(atPath: keyPath), !force {
        fail("a key already exists at \(keyPath) — pass --force to overwrite (this invalidates every signed bundle)")
    }
    let key = Curve25519.Signing.PrivateKey()
    let directory = (keyPath as NSString).deletingLastPathComponent
    try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    try! key.rawRepresentation.base64EncodedString().write(toFile: keyPath, atomically: true, encoding: .utf8)
    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)
    print("private key written to \(keyPath) (keep this out of the repo)")
    print("public key: \(key.publicKey.rawRepresentation.base64EncodedString())")

case "sign":
    guard let siteDir else { fail("--site-dir is required") }
    let key = loadPrivateKey()
    let files = loadFiles(siteDir)
    let existing = SignedBundle.load(directory: siteDir)
    let newVersion = version ?? ((existing?.version ?? 0) + 1)
    let payload = SignedBundle.canonicalPayload(version: newVersion, files: files)
    let signature = try! key.signature(for: payload)
    let bundle = SignedBundle(version: newVersion, files: files, signature: signature)
    try! bundle.write(to: siteDir)
    print("signed version \(newVersion) (\(files.count) files) in \(siteDir)")
    print("public key: \(key.publicKey.rawRepresentation.base64EncodedString())")

case "verify":
    guard let siteDir else { fail("--site-dir is required") }
    guard let bundle = SignedBundle.load(directory: siteDir) else {
        fail("no signed bundle found in \(siteDir)")
    }
    guard let publicKey = ConvoKeys.publicKey() else {
        fail("the built-in public key is not set")
    }
    if bundle.isValid(publicKey: publicKey) {
        print("version \(bundle.version): signature OK (\(bundle.files.count) files)")
    } else {
        fail("version \(bundle.version): SIGNATURE INVALID")
    }

default:
    FileHandle.standardError.write(Data("error: unknown command \(command)\n\(usage)\n".utf8))
    exit(2)
}
