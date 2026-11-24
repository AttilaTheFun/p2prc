// CI's own steps for Convo (.github/workflows/ci.yml), in place of shell:
//
//   convo_ci stamp-version <version>     the version where the apps show it
//   convo_ci proof --pictures <dir> --out <dir> --version <v> [--tests-log <file>]
//   convo_ci team --profiles <file>…     the team, from its signing profiles
//   convo_ci verify-alphas …             a draft's Alphas checked before they're promoted
//
// The Info.plists' CFBundleShortVersionString is tools/ci/version_from_tags.sh's
// (it picks the version); stamp-version writes the same into Client.version
// (Settings' Version row on every platform) and the Android app's
// version_name, in the checkout, never committed.
import ArgumentParser
import Crypto
import Foundation

@main
struct ConvoCI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "convo_ci",
        abstract: "CI's own steps for Convo.",
        subcommands: [StampVersion.self, Proof.self, Team.self, VerifyAlphas.self])
}

struct Failure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// The checkout: BUILD_WORKSPACE_DIRECTORY under `bazel run`, else the current directory.
func checkout() -> URL {
    let path = ProcessInfo.processInfo.environment["BUILD_WORKSPACE_DIRECTORY"] ?? FileManager.default.currentDirectoryPath
    return URL(fileURLWithPath: path, isDirectory: true)
}

struct StampVersion: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "stamp-version",
        abstract: "Stamp the release's version into Client.version and the Android app's version_name.")

    @Argument(help: "The version, MAJOR.MINOR.N.")
    var version: String

    @Option(help: "The commit the build is of: ConvoCommit in the Apple apps' Info.plists, which their signatures seal.")
    var commit: String?

    func validate() throws {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) else {
            throw ValidationError("\(version) is not MAJOR.MINOR.N")
        }
    }

    func run() throws {
        let root = checkout()
        try stamp(root.appendingPathComponent("libraries/convo_app/Sources/Client.swift"),
                  prefix: "public static let version = \"")
        try stamp(root.appendingPathComponent("applications/p2prc_android/BUILD.bazel"),
                  prefix: "version_name = \"")
        if let commit {
            guard commit.count == 40, commit.allSatisfy(\.isHexDigit) else { throw ValidationError("\(commit) is not a commit") }
            for plist in ["applications/p2prc_ios/Info.plist", "applications/p2prc_macos/Info.plist"] {
                let file = root.appendingPathComponent(plist)
                var text = try String(contentsOf: file, encoding: .utf8)
                guard !text.contains("<key>ConvoCommit</key>"), let end = text.range(of: "</dict>", options: .backwards) else {
                    throw Failure("\(plist) has a ConvoCommit already, or no </dict>")
                }
                text.insert(contentsOf: "  <key>ConvoCommit</key><string>\(commit)</string>\n", at: end.lowerBound)
                try text.write(to: file, atomically: true, encoding: .utf8)
            }
        }
        print("convo_ci: \(version) stamped into Client.version and the Android app's version_name\(commit == nil ? "" : ", the commit into the Info.plists")")
    }

    /// The one line holding `prefix`, its quoted value made the version.
    func stamp(_ file: URL, prefix: String) throws {
        let text = try String(contentsOf: file, encoding: .utf8)
        var lines = text.components(separatedBy: "\n")
        let matches = lines.indices.filter { lines[$0].contains(prefix) }
        guard matches.count == 1, let at = matches.first else {
            throw Failure("\(file.lastPathComponent): expected one line with \(prefix)…\", found \(matches.count)")
        }
        let line = lines[at]
        guard let start = line.range(of: prefix), let end = line[start.upperBound...].firstIndex(of: "\"") else {
            throw Failure("\(file.lastPathComponent): \(prefix)…\" has no closing quote")
        }
        lines[at] = String(line[..<start.upperBound]) + version + String(line[end...])
        try lines.joined(separator: "\n").write(to: file, atomically: true, encoding: .utf8)
    }
}

/// Reviews' proof, format 2: proof.json and screens/<id>.png (and logs/).
struct Proof: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Assemble the proof from the verify job's pictures and the tests' log.",
        discussion: """
            Each picture <platform>-<name>.png becomes the item <platform>/<name> (ios-thread.png: ios/thread). \
            Fails when there is no picture, or when the tests' log says they failed.
            """)

    @Option(help: "The folder of pictures (PNG).")
    var pictures: String

    @Option(help: "The proof's folder, made here.")
    var out: String

    @Option(help: "The release's version.")
    var version: String

    @Option(help: "The end-to-end run's log (tools/e2e's pair.log): its result an item of the proof.")
    var testsLog: String?

    struct Item: Encodable {
        var id: String
        var kind: String
        var title: String
        var file: String?
        var sha256: String?
        var width: Int?
        var height: Int?
        var result: String?
        var tests: Int?
        var failures: Int?
        var log: String?
    }

    struct Document: Encodable {
        var format = 2
        var app = "Convo"
        var version: String
        var repository: String
        var commit: String
        var run: Int?
        var made: String
        var items: [Item]
    }

    func run() throws {
        let files = FileManager.default
        let source = URL(fileURLWithPath: pictures, isDirectory: true)
        let proof = URL(fileURLWithPath: out, isDirectory: true)
        // Hidden files aren't pictures (macOS's "._" AppleDouble files among them).
        let names = try files.contentsOfDirectory(atPath: source.path).filter { $0.hasSuffix(".png") && !$0.hasPrefix(".") }.sorted()
        guard !names.isEmpty else { throw Failure("no pictures in \(pictures)") }
        var items: [Item] = []
        for name in names {
            let stem = String(name.dropLast(4))
            guard let dash = stem.firstIndex(of: "-") else {
                throw Failure("\(name) is not <platform>-<name>.png")
            }
            let platform = String(stem[..<dash])
            let screen = String(stem[stem.index(after: dash)...])
            let id = "\(platform)/\(screen)"
            let file = "screens/\(id).png"
            let target = proof.appendingPathComponent(file)
            try files.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            if files.fileExists(atPath: target.path) { try files.removeItem(at: target) }
            try files.copyItem(at: source.appendingPathComponent(name), to: target)
            let data = try Data(contentsOf: target)
            let (width, height) = try size(of: data, name: name)
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            items.append(Item(id: id, kind: "screen", title: title(platform: platform, screen: screen), file: file,
                              sha256: sha, width: width, height: height))
        }
        var failed = false
        if let testsLog {
            let log = try String(contentsOfFile: testsLog, encoding: .utf8)
            try files.createDirectory(at: proof.appendingPathComponent("logs"), withIntermediateDirectories: true)
            try log.write(to: proof.appendingPathComponent("logs/e2e.txt"), atomically: true, encoding: .utf8)
            // tools/e2e/run_pair.sh's log, judged by what happened, not by its retries ("not loaded yet,
            // reopening", a wait that timed out and was tried again): both messages arrived, the one sent after
            // reopening the thread arrived, both peer links went through TURN (relay on both ends), no trap,
            // and the run reached its end.
            let lines = log.split(separator: "\n").map(String.init)
            func line(_ prefix: String) -> String? { lines.last { $0.contains(" \(prefix) ") } }
            let checks: [(String, Bool)] = [
                // Each side's last view of the thread: b's, and a's once it reopened it (a's first snapshot can
                // be taken before its own message is drawn).
                ("both messages", ["b thread:", "a after reopen:"].allSatisfy { line($0)?.contains("hello from a") == true && line($0)?.contains("hello from b") == true }),
                ("the message after reopening", line("a after reopen:")?.contains("after reopen") == true),
                ("a relayed link on both ends", ["ice a:", "ice b:"].allSatisfy { line($0)?.contains("connected relay/relay") == true }),
                ("no trap", line("traps:")?.hasSuffix("traps: 0") == true),
                ("the run's end", lines.contains { $0.hasSuffix(" done") }),
            ]
            let missing = checks.filter { !$0.1 }.map(\.0)
            failed = !missing.isEmpty
            if failed { print("convo_ci: the end-to-end run is missing \(missing.joined(separator: ", "))") }
            items.append(Item(id: "tests/e2e", kind: "tests",
                              title: "End to end: two clients paired and messaging through the p2prc nodes, their link through TURN",
                              result: failed ? "failed" : "passed", tests: checks.count, failures: missing.count,
                              log: "logs/e2e.txt"))
        }
        let environment = ProcessInfo.processInfo.environment
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let document = Document(
            version: version,
            repository: environment["GITHUB_REPOSITORY"] ?? "AttilaTheFun/convo",
            commit: environment["GITHUB_SHA"] ?? "",
            run: environment["GITHUB_RUN_ID"].flatMap(Int.init),
            made: formatter.string(from: Date()),
            items: items)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(document).write(to: proof.appendingPathComponent("proof.json"))
        print("convo_ci: the proof, \(items.count) items, in \(out)")
        if failed { throw Failure("the end-to-end run failed (its log is the proof's logs/e2e.txt)") }
    }

    /// A PNG's width and height, from its IHDR (bytes 16 to 24).
    func size(of data: Data, name: String) throws -> (Int, Int) {
        let bytes = [UInt8](data.prefix(24))
        guard bytes.count == 24, bytes[0 ..< 8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] else {
            throw Failure("\(name) is not a PNG")
        }
        let int = { (at: Int) in bytes[at ..< at + 4].reduce(0) { $0 << 8 | Int($1) } }
        return (int(16), int(20))
    }

    func title(platform: String, screen: String) -> String {
        let platforms = ["ios": "iPhone", "ipad": "iPad", "macos": "Mac", "android": "Android", "web": "Web"]
        let words = screen.replacingOccurrences(of: "-", with: " ").replacingOccurrences(of: "_", with: " ")
        return "\(platforms[platform] ?? platform): \(words.prefix(1).uppercased() + words.dropFirst())"
    }
}

/// The team the app is signed by, read from the signing profiles released
/// to the job (a .tar or .tar.gz of them): the TeamIdentifier of the profile whose application-identifier is
/// <team>.<bundle id>. Printed alone, for the build's settings; no team id
/// is kept in the repository or GitHub.
struct Team: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Print the team of the bundle id's profile in the profiles' archives.")

    @Option(help: "The app's bundle id.")
    var bundleID = "com.LoganShire.P2PRC"

    @Option(parsing: .upToNextOption, help: "The profiles' archives (.tar or .tar.gz).")
    var profiles: [String]

    func run() throws {
        let files = FileManager.default
        let work = files.temporaryDirectory.appendingPathComponent("convo-ci-team-\(UUID().uuidString)")
        try files.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? files.removeItem(at: work) }
        var teams: Set<String> = []
        for (n, archive) in profiles.enumerated() {
            let folder = work.appendingPathComponent("\(n)")
            try files.createDirectory(at: folder, withIntermediateDirectories: true)
            let tar = Process()
            tar.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            tar.arguments = ["tar", "-xf", archive, "-C", folder.path]
            try tar.run()
            tar.waitUntilExit()
            guard tar.terminationStatus == 0 else { throw Failure("\(archive) is not a tar of profiles") }
            for case let url as URL in files.enumerator(at: folder, includingPropertiesForKeys: nil) ?? FileManager.DirectoryEnumerator() {
                guard ["mobileprovision", "provisionprofile"].contains(url.pathExtension),
                      let plist = Self.plist(in: try Data(contentsOf: url)),
                      let team = (plist["TeamIdentifier"] as? [String])?.first,
                      let entitlements = plist["Entitlements"] as? [String: Any],
                      let identifier = entitlements["application-identifier"] as? String ?? entitlements["com.apple.application-identifier"] as? String,
                      identifier == "\(team).\(bundleID)" else { continue }
                teams.insert(team)
            }
        }
        guard teams.count == 1, let team = teams.first else {
            throw Failure(teams.isEmpty ? "no profile for \(bundleID) in the archives" : "profiles for \(bundleID) of more than one team")
        }
        print(team)
    }

    /// The property list a profile's CMS envelope carries, as XML.
    static func plist(in data: Data) -> [String: Any]? {
        let bytes = [UInt8](data)
        guard let start = find(Array("<?xml".utf8), in: bytes, from: 0),
              let end = find(Array("</plist>".utf8), in: bytes, from: start) else { return nil }
        let xml = Data(bytes[start ..< end + 8])
        return (try? PropertyListSerialization.propertyList(from: xml, format: nil)) as? [String: Any]
    }

    static func find(_ needle: [UInt8], in haystack: [UInt8], from: Int) -> Int? {
        guard haystack.count >= needle.count, from <= haystack.count - needle.count else { return nil }
        for i in from ... haystack.count - needle.count where haystack[i] == needle[0] && Array(haystack[i ..< i + needle.count]) == needle { return i }
        return nil
    }
}

/// A program's run: its status and output.
@discardableResult
func run(_ arguments: [String], input: String? = nil) throws -> (status: Int32, output: String, error: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = arguments
    let out = Pipe(), err = Pipe()
    process.standardOutput = out
    process.standardError = err
    try process.run()
    let output = out.fileHandleForReading.readDataToEndOfFile()
    let error = err.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: output, as: UTF8.self), String(decoding: error, as: UTF8.self))
}

func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

/// The release job's check of a draft's Alphas before it promotes them:
/// anyone with write access to the repository can replace a draft's assets, but only a granted CI job holds the keys that sign them.
/// So each is trusted for what its own signature proves, nothing for what
/// builds.json says:
/// - an Apple app: every piece of code's signature verified up to Apple's
///   root (pinned here), its code matching its signed code directory, its
///   Info.plist and every sealed resource matching their hashes, every file
///   sealed, nested code likewise; the signer the team's (Developer ID on
///   the Mac, development on iPhone); the bundle id and version the release's;
/// - an APK: signed by the one pinned certificate, the package and
///   versionName the release's.
struct VerifyAlphas: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "verify-alphas",
        abstract: "Check a draft's Alphas by their own signatures before they're promoted.")

    /// Apple Inc. Root's certificate (tools/ci/AppleIncRootCertificate.cer), by its SHA-256.
    static let appleRootSHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"

    @Option(help: "The release's version (its tag without the v).") var version: String
    @Option(help: "The release's commit: each Apple app's sealed ConvoCommit.") var commit: String
    @Option(help: "The team the Apple apps must be signed by.") var team: String
    @Option(help: "The Android release certificate's SHA-256.") var pin: String
    @Option(help: "Apple Inc. Root's certificate (DER).") var appleRoot: String
    @Option(help: "The pinned rcodesign.") var rcodesign: String
    @Option(help: "The pinned java.") var java: String
    @Option(help: "The pinned apksigner.jar.") var apksigner: String
    @Option(help: "The pinned aapt2.") var aapt2: String
    @Option(help: "The Apple apps' bundle id.") var bundleID = "com.LoganShire.P2PRC"
    @Option(help: "The Android app's package.") var androidPackage = "com.loganshire.p2prc"
    @Argument(help: "The Alphas: .ipa, a Mac app's .zip, .apk.") var files: [String]

    func run() throws {
        let fm = FileManager.default
        let work = fm.temporaryDirectory.appendingPathComponent("convo-verify-\(UUID().uuidString)")
        try fm.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: work) }
        let root = try Data(contentsOf: URL(fileURLWithPath: appleRoot))
        guard hex(sha256(root)) == Self.appleRootSHA256 else { throw Failure("\(appleRoot) is not Apple Inc. Root") }
        let rootPEM = work.appendingPathComponent("root.pem").path
        guard try ConvoCI_run(["openssl", "x509", "-inform", "DER", "-in", appleRoot, "-out", rootPEM]).status == 0 else { throw Failure("Apple's root didn't convert") }
        // The whole set: one of each, so a draft missing a platform isn't promoted short.
        for kind in [".ipa", ".zip", ".apk"] {
            let count = files.filter { $0.hasSuffix(kind) }.count
            guard count == 1 else { throw Failure("the Alphas hold \(count) \(kind), not one") }
        }
        for (n, file) in files.enumerated() {
            let name = (file as NSString).lastPathComponent
            if file.hasSuffix(".apk") {
                try checkAPK(file)
            } else if file.hasSuffix(".ipa") || file.hasSuffix(".zip") {
                let folder = work.appendingPathComponent("\(n)")
                try fm.createDirectory(at: folder, withIntermediateDirectories: true)
                guard try ConvoCI_run(["unzip", "-q", file, "-d", folder.path]).status == 0 else { throw Failure("\(name) isn't a zip") }
                let mac = file.hasSuffix(".zip")
                let parent = mac ? folder : folder.appendingPathComponent("Payload")
                let apps = try fm.contentsOfDirectory(atPath: parent.path).filter { $0.hasSuffix(".app") }
                guard apps.count == 1 else { throw Failure("\(name) holds \(apps.count) apps") }
                let checker = AppleChecker(rcodesign: rcodesign, rootPEM: rootPEM, team: team, mac: mac, work: work)
                let top = try checker.bundle(parent.appendingPathComponent(apps[0]))
                guard top.bundleID == bundleID else { throw Failure("\(name) is \(top.bundleID ?? "?"), not \(bundleID)") }
                guard top.version == version else { throw Failure("\(name) is version \(top.version ?? "?"), not \(version)") }
                guard top.commit == commit else { throw Failure("\(name) was built from \(top.commit ?? "no recorded commit"), not \(commit)") }
            } else {
                throw Failure("\(name) is no Alpha this checks")
            }
            print("convo_ci: \(name) verified")
        }
    }

    func checkAPK(_ file: String) throws {
        let name = (file as NSString).lastPathComponent
        let verified = try ConvoCI_run([java, "-jar", apksigner, "verify", "--print-certs", file])
        guard verified.status == 0 else { throw Failure("\(name)'s signature doesn't verify: \(verified.error.prefix(300))") }
        let digests = verified.output.split(separator: "\n").compactMap { line -> String? in
            guard line.contains("certificate SHA-256 digest:") else { return nil }
            return line.split(separator: ":").last.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        }
        let pinned = pin.replacingOccurrences(of: ":", with: "").lowercased()
        guard !pinned.isEmpty, Set(digests) == [pinned] else { throw Failure("\(name) isn't signed by the pinned certificate alone") }
        let badging = try ConvoCI_run([aapt2, "dump", "badging", file])
        guard badging.status == 0, let line = badging.output.split(separator: "\n").first(where: { $0.hasPrefix("package:") }) else {
            throw Failure("\(name)'s manifest wasn't read")
        }
        func field(_ key: String) -> String? {
            guard let range = line.range(of: key + "='") else { return nil }
            return String(line[range.upperBound...].prefix { $0 != "'" })
        }
        guard field("name") == androidPackage else { throw Failure("\(name) is \(field("name") ?? "?"), not \(androidPackage)") }
        guard field("versionName") == version else { throw Failure("\(name) is version \(field("versionName") ?? "?"), not \(version)") }
    }
}

/// `run` under a name that the commands' own `run()` doesn't hide.
@discardableResult
func ConvoCI_run(_ arguments: [String]) throws -> (status: Int32, output: String, error: String) { try run(arguments) }

func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

/// One Apple app's signatures, checked as macOS and iOS check them.
struct AppleChecker {
    let rcodesign: String
    let rootPEM: String
    let team: String
    let mac: Bool
    let work: URL

    struct Code { var cdhash: Data; var identifier: String; var commonName: String }
    struct Bundle { var bundleID: String?; var version: String?; var commit: String?; var cdhash: Data }

    /// A bundle (an app, an extension, a framework): its code, Info.plist and sealed resources.
    func bundle(_ url: URL) throws -> Bundle {
        let fm = FileManager.default
        // A Mac bundle (Contents/), a Mac framework (Versions/Current/, its
        // Info.plist in Resources/), or an iPhone one (flat).
        let contents: URL, infoURL: URL, exeFolder: URL
        if fm.fileExists(atPath: url.appendingPathComponent("Contents").path) {
            contents = url.appendingPathComponent("Contents"); infoURL = contents.appendingPathComponent("Info.plist")
            exeFolder = contents.appendingPathComponent("MacOS")
        } else if fm.fileExists(atPath: url.appendingPathComponent("Versions/Current").path) {
            contents = url.appendingPathComponent("Versions/Current").resolvingSymlinksInPath()
            infoURL = contents.appendingPathComponent("Resources/Info.plist"); exeFolder = contents
        } else {
            contents = url; infoURL = url.appendingPathComponent("Info.plist"); exeFolder = url
        }
        let resourcesURL = contents.appendingPathComponent("_CodeSignature/CodeResources")
        let infoData = try? Data(contentsOf: infoURL)
        let info = infoData.flatMap { try? PropertyListSerialization.propertyList(from: $0, format: nil) as? [String: Any] } ?? [:]
        guard let executable = info["CFBundleExecutable"] as? String else { throw Failure("\(url.lastPathComponent) names no executable") }
        let exePath = exeFolder.appendingPathComponent(executable)
        let resources = try Data(contentsOf: resourcesURL)
        let code = try self.code(exePath, info: infoData, resources: resources)
        let bundleID = info["CFBundleIdentifier"] as? String
        guard code.identifier == bundleID else { throw Failure("\(url.lastPathComponent)'s signature is for \(code.identifier), not \(bundleID ?? "?")") }
        try sealed(contents, resources: resources, executable: exePath, url: url)
        return Bundle(bundleID: bundleID, version: info["CFBundleShortVersionString"] as? String,
                      commit: info["ConvoCommit"] as? String, cdhash: code.cdhash)
    }

    /// Every file in the bundle sealed by CodeResources, and matching it.
    func sealed(_ contents: URL, resources: Data, executable: URL, url: URL) throws {
        let fm = FileManager.default
        guard let plist = try PropertyListSerialization.propertyList(from: resources, format: nil) as? [String: Any],
              let files = plist["files2"] as? [String: Any] else { throw Failure("\(url.lastPathComponent)'s CodeResources has no files2") }
        var covered: Set<String> = []
        var nested: [String] = []
        for (path, value) in files {
            let file = contents.appendingPathComponent(path)
            let entry = value as? [String: Any] ?? [:]
            let optional = entry["optional"] as? Bool ?? false
            if let target = entry["symlink"] as? String {
                guard (try? fm.destinationOfSymbolicLink(atPath: file.path)) == target else { throw Failure("\(path) isn't the link it was sealed as") }
            } else if let hash = entry["hash2"] as? Data ?? value as? Data {
                guard let data = try? Data(contentsOf: file) else {
                    if optional { continue }
                    throw Failure("\(path), sealed, is missing")
                }
                guard sha256(data) == hash || (value is Data && Data(Insecure.SHA1.hash(data: data)) == hash) else { throw Failure("\(path) isn't what was sealed") }
            } else if let cdhash = entry["cdhash"] as? Data {
                var isDirectory: ObjCBool = false
                guard fm.fileExists(atPath: file.path, isDirectory: &isDirectory) else { throw Failure("\(path), sealed code, is missing") }
                let actual = isDirectory.boolValue ? try bundle(file).cdhash : try code(file, info: nil, resources: nil).cdhash
                guard actual == cdhash else { throw Failure("\(path) isn't the code that was sealed") }
                nested.append(path)
            } else {
                throw Failure("\(path)'s seal isn't understood")
            }
            covered.insert(path)
        }
        // Nothing unsealed beside them (macOS refuses an app with one).
        let base = contents.path.hasSuffix("/") ? contents.path : contents.path + "/"
        let skip: Set<String> = ["Info.plist", "Resources/Info.plist", "PkgInfo", "_CodeSignature/CodeResources",
                                 executable.path.hasPrefix(base) ? String(executable.path.dropFirst(base.count)) : executable.lastPathComponent]
        for case let relative as String in fm.enumerator(atPath: contents.path) ?? FileManager.DirectoryEnumerator() {
            let full = contents.appendingPathComponent(relative).path
            var isDirectory: ObjCBool = false
            let isLink = (try? fm.destinationOfSymbolicLink(atPath: full)) != nil
            if !isLink, fm.fileExists(atPath: full, isDirectory: &isDirectory), isDirectory.boolValue { continue }
            if skip.contains(relative) || covered.contains(relative) { continue }
            // A Mac bundle's stapled notarization ticket (Apple's, outside the seal by design).
            if relative == "CodeResources", mac { continue }
            if nested.contains(where: { relative.hasPrefix($0 + "/") }) { continue }
            throw Failure("\(url.lastPathComponent) holds \(relative), which its signature doesn't seal")
        }
    }

    /// A Mach-O's signature: its code matching its code directory, the
    /// directory signed by a certificate that chains to Apple's root, the
    /// team's, of the right kind; its Info.plist and CodeResources the sealed ones.
    func code(_ file: URL, info: Data?, resources: Data?) throws -> Code {
        let name = file.lastPathComponent
        let verified = try ConvoCI_run([rcodesign, "verify", file.path])
        guard verified.status == 0 else { throw Failure("\(name)'s code doesn't match its signature: \(verified.error.suffix(300))") }
        let tag = UUID().uuidString
        let cms = work.appendingPathComponent("\(tag).cms").path, cd = work.appendingPathComponent("\(tag).cd").path
        let signer = work.appendingPathComponent("\(tag).pem").path
        // The raw extracts are binary: rcodesign's standard output straight to files.
        guard try ConvoCI_run(["sh", "-c", "\"$0\" extract cms-raw \"$1\" > \"$2\" && \"$0\" extract code-directory-raw \"$1\" > \"$3\"", rcodesign, file.path, cms, cd]).status == 0 else {
            throw Failure("\(name)'s signature wasn't read")
        }
        // Apple's leaf certificates carry critical extensions of Apple's own, which openssl doesn't know.
        let checked = try ConvoCI_run(["openssl", "cms", "-verify", "-inform", "DER", "-in", cms, "-binary", "-content", cd,
                                       "-CAfile", rootPEM, "-purpose", "any", "-ignore_critical", "-signer", signer, "-out", "/dev/null"])
        guard checked.status == 0 else { throw Failure("\(name)'s signature doesn't verify to Apple's root") }
        let subject = try ConvoCI_run(["openssl", "x509", "-in", signer, "-noout", "-subject", "-nameopt", "RFC2253,sep_comma_plus"]).output
        func part(_ key: String) -> String? {
            subject.replacingOccurrences(of: "subject=", with: "").components(separatedBy: ",")
                .first { $0.hasPrefix(key + "=") }.map { String($0.dropFirst(key.count + 1)) }
        }
        guard part("OU") == team else { throw Failure("\(name) is signed by another team") }
        let commonName = part("CN") ?? ""
        // The certificate's kind by Apple's policy extension, not its name: Developer ID Application
        // (1.2.840.113635.100.6.1.13) on the Mac, iPhone development (…6.1.2) on iPhone.
        let policy = mac ? "1.2.840.113635.100.6.1.13" : "1.2.840.113635.100.6.1.2"
        let text = try ConvoCI_run(["openssl", "x509", "-in", signer, "-noout", "-text"]).output
        guard text.range(of: policy + ":") != nil else {
            throw Failure("\(name) is signed by \(commonName.components(separatedBy: ":").first ?? "?"), not \(mac ? "Developer ID Application" : "Apple Development")")
        }
        // One architecture: a universal binary's other slices would go unchecked.
        let magic = try FileHandle(forReadingFrom: file).read(upToCount: 4) ?? Data()
        let fat: [Data] = [[0xca, 0xfe, 0xba, 0xbe], [0xbe, 0xba, 0xfe, 0xca], [0xca, 0xfe, 0xba, 0xbf], [0xbf, 0xba, 0xfe, 0xca]].map { Data($0) }
        guard !fat.contains(magic) else {
            throw Failure("\(name) is a universal binary: CI builds one architecture")
        }
        // The code directory: big-endian fields (xnu's cs_blobs.h).
        let directory = try Data(contentsOf: URL(fileURLWithPath: cd))
        let d = [UInt8](directory)
        guard d.count > 44 else { throw Failure("\(name)'s code directory is short") }
        let u32 = { (at: Int) in Int(d[at]) << 24 | Int(d[at + 1]) << 16 | Int(d[at + 2]) << 8 | Int(d[at + 3]) }
        let hashOffset = u32(16), identOffset = u32(20), specialSlots = u32(24), hashSize = Int(d[36])
        guard hashSize == 32, identOffset < d.count, hashOffset <= d.count else { throw Failure("\(name)'s code directory isn't SHA-256") }
        let identifier = String(decoding: d[identOffset...].prefix { $0 != 0 }, as: UTF8.self)
        func slot(_ n: Int) -> Data? {
            guard n <= specialSlots, hashOffset - n * hashSize >= 0 else { return nil }
            return Data(d[(hashOffset - n * hashSize) ..< (hashOffset - n * hashSize + hashSize)])
        }
        if let info { guard slot(1) == sha256(info) else { throw Failure("\(name)'s Info.plist isn't the signed one") } }
        if let resources { guard slot(3) == sha256(resources) else { throw Failure("\(name)'s CodeResources isn't the signed one") } }
        return Code(cdhash: Data(sha256(directory).prefix(20)), identifier: identifier, commonName: commonName)
    }
}
