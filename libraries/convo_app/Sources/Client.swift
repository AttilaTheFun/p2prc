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
import ConvoCore
import ConvoMLS
import ConvoNet
import ConvoServices
import ConvoSession
import Observation
import SwiftUI

/// Someone this device has a conversation with: their Convo identity, the
/// name assigned here, and the group the two of you share. Persisted.
public struct Contact: Codable, Identifiable, Equatable {
    /// The identity key, hex — identity and addressing are the same thing.
    public let id: String
    /// The name the person on *this* device assigned. Starts as the name
    /// their KeyPackage carried; renaming is local and private.
    public var name: String
    /// The two-member group's id, hex.
    public var groupID: String
    /// True once the genesis handshake completed: their KeyPackage was
    /// signed by the identity in the invite, and the MLS commit reached
    /// them, so they hold the key they claim.
    public var trusted: Bool

    public init(id: String, name: String, groupID: String, trusted: Bool) {
        self.id = id; self.name = name; self.groupID = groupID; self.trusted = trusted
    }
}

/// One conversation: a Convo group of two, its history (`GroupState`), the
/// peer data channel that carries live delivery and calls, and what the
/// screen shows for it. Plain class, not observable — the Client bumps its
/// `revision` after any mutation, which is what the views watch.
public final class Conversation: Identifiable {
    public let contactID: String
    public var id: String { contactID }
    public let groupID: Hash32
    let state: GroupState
    /// The host connection this conversation's data channel rides: the
    /// group id, so a reconnect replaces the same connection.
    var transportID: String { groupID.hex }
    public internal(set) var connected = false
    /// The data channel on the current connection has opened (and not
    /// closed): what lets a connection that dips to "disconnected" and
    /// recovers be counted as up again — its channel never re-opens.
    var channelOpen = false
    /// The connection's last reported state ("connected", "disconnected",
    /// …), for judging a "disconnected" once its grace has run out.
    var linkState = ""
    /// What the link is doing while down, for the info pane.
    public internal(set) var linkStatus = ""
    public internal(set) var messages: [Client.Message] = []
    public internal(set) var callState: Client.CallState = .none
    /// Whether the call (ringing, declined, or live) carries video.
    public internal(set) var callVideo = false
    /// What went wrong with the last call, for the chat's footer ("they
    /// couldn't join the call: …", "no answer"); cleared by the next call.
    public internal(set) var callNote = ""
    /// Bumped by every call placed, so a ring timeout ends only its own call.
    var callSerial = 0
    /// Always true for a group that came through the handshake.
    public internal(set) var peerVerified = true
    /// The name the peer put in their KeyPackage.
    public var peerNick: String { state.roster.first { $0.body.identityPk.hex == contactID }?.body.name ?? "" }
    /// Where the conversation stands (§6), for the details pane:
    /// "3 of 5 committed", "all committed".
    public internal(set) var chainStatus = "nothing sent yet"
    /// Kept for the details pane and the debug hooks; always false in
    /// v1.0 (a committed head that fails §4 is simply not built on).
    public internal(set) var unsound = false
    /// The genesis record still has to reach every home node (§13).
    var genesisPublished: Set<String> = []
    var carrySigs: [(UInt8, [UInt8])] = []
    /// A recovery fork in flight (§9.2, §9.8): its salt, and this side's
    /// half of the handshake.
    var forkSalt: Hash32?
    var forkCreator: HandshakeCreator?
    var forkJoiner: HandshakeJoiner?
    var forkScheduled = false
    /// §9.2: since when (seconds) this member has been missing data under
    /// a head another member attested; nil when everything is held.
    var syncingSince: Double?
    /// Control texts already acted on.
    var handledControls: Set<String> = []
    /// The parent conversation's messages, shown above this group's own
    /// after a fork (§9.4: history stays visible; it just stops growing).
    public internal(set) var archived: [Client.Message] = []
    var reconnecting = false
    var offering = false
    /// Hashes already acked to each node, so a re-fetch does not re-ack.
    var acked: Set<String> = []
    /// Attachments opened and handed to the host: message hash → URL.
    var imageURLs: [String: String] = [:]
    var fetchingBlobs: Set<String> = []

    init(contactID: String, state: GroupState) {
        self.contactID = contactID
        self.groupID = state.groupID
        self.state = state
    }
}

/// The Convo client: one identity, many contacts, one two-member group per
/// contact, on the Convo Protocol (Docs/ in convo_protocol).
///
/// Everything here is transport-agnostic and side-effect-free except through
/// `ConvoServices.host`. The host moves bytes; this decides what the bytes
/// mean. Every byte that leaves is protocol wire: MLS-sealed messages,
/// signed attestations, handshake and signaling frames. The host never sees
/// a plaintext message or a private key.
///
/// Not actor-isolated and without Swift concurrency: wasm is
/// single-threaded, every host callback lands on the one thread there is,
/// and the view layer this compiles against is not MainActor-isolated
/// either. `ConvoSession` is the protocol's synchronous core for exactly
/// this reason.
@Observable
public final class Client {
    /// The release, as the tag names it (v0.15): shown in Settings on every
    /// platform. Keep in step with the iOS and macOS Info.plist and the
    /// Android version_name.
    public static let version = "0.2.0"

    public struct Message: Identifiable, Equatable, Codable {
        public let id: String
        public let sender: String
        public let senderName: String
        public let text: String
        public let timestamp: Double
        public var mine: Bool
        /// §5–§7: "sent" (held by hosts or peers), "attested" (a quorum
        /// signed a head above it), "locked" (on the chain).
        public var state: String = "sent"
        /// An attachment (kind 4): where the picture is showable from once
        /// its blob is fetched and opened, and its shape until then.
        public var image: String? = nil
        public var aspect: Double? = nil
        /// Reactions (kind 3) folded onto this message.
        public var reactions: [ReactionSummary]? = nil
    }

    public struct ReactionSummary: Equatable, Codable {
        public let emoji: String
        public let count: Int
        public let mine: Bool
    }

    /// The pairing flow's state — one pairing at a time, shown in a sheet.
    public enum Phase: Equatable {
        case starting
        /// No identity yet: the person creates one or imports one.
        case needsIdentity
        case idle
        case inviting          // showing a code, waiting for someone to scan
        case joining           // scanned a code, running the handshake
        case failed(String)
    }

    public private(set) var phase: Phase = .starting { didSet { touch() } }
    public private(set) var contacts: [Contact] = [] { didSet { touch() } }
    /// Bumped after any mutation inside a Conversation, and by every
    /// published property above and below — the reactivity signal for
    /// state the conversations hold as plain classes, and what `observe`
    /// reports on.
    public private(set) var revision = 0
    public var pairingVisible = false { didSet { touch() } }
    public private(set) var pendingNaming: String? { didSet { touch() } }
    public private(set) var lastPairedContact: String? { didSet { touch() } }
    /// Another device of ours joining (Settings → Add a device): the code
    /// it scans, and how that is going on either end.
    public private(set) var handoffLink: String = "" { didSet { touch() } }
    public private(set) var handoffQRImage: String = "" { didSet { touch() } }
    public private(set) var handoffStatus: String = "" { didSet { touch() } }
    public private(set) var inviteLink: String = "" { didSet { touch() } }
    public private(set) var inviteQRImage: String = "" { didSet { touch() } }
    public private(set) var status: String = "" { didSet { touch() } }
    public var openContact: String? { didSet { touch() } }
    public private(set) var detailsRequested = false { didSet { touch() } }
    public var debugOpenContact: String? { didSet { touch() } }
    public var nick: String = "" { didSet { touch() } }
    public private(set) var capabilities = NetworkCapabilities.browser { didSet { touch() } }
    /// The nodes confirmed healthy, freshest first (for Settings).
    public private(set) var signalingServers: [KnownServer] = [] { didSet { touch() } }
    public private(set) var selfFingerprint: String = "" { didSet { touch() } }
    public private(set) var peerFingerprint: String = "" { didSet { touch() } }

    /// Observation without Combine: `body` runs synchronously, on the
    /// client's thread (the main thread in the apps), after every change
    /// the client publishes (any property above, any conversation
    /// mutation). Hosts use it for chrome that follows the client (the Mac
    /// titlebar, the video window) and the test hooks.
    public typealias Observer = UUID
    @ObservationIgnored private var observers: [Observer: () -> Void] = [:]

    @discardableResult
    public func observe(_ body: @escaping () -> Void) -> Observer {
        let id = UUID()
        observers[id] = body
        return id
    }

    public func stopObserving(_ observation: Observer) { observers[observation] = nil }

    public func setDetails(_ on: Bool) {
        guard detailsRequested != on else { return }
        detailsRequested = on
    }

    public func toggleDetails() { setDetails(!detailsRequested) }

    /// The identity key, hex (64 characters).
    public private(set) var selfID: String = ""
    private var identity: ConvoIdentity?
    private var storageKey: SymmetricKey?
    public var shownContact: String? {
        if let open = openContact ?? debugOpenContact { return open }
        if pairingVisible { return nil }
        return lastPairedContact ?? conversations.first?.contactID
    }
    private var pageBase: String = ""
    /// The nodes this client knows (Part III §24): health-checked with
    /// backoff, bounded at ten, persisted.
    private var servers = ServerDirectory(limit: 10)
    /// Each healthy node's signing key, from `/v1/node`.
    private var nodeKeys: [String: Hash32] = [:]

    /// Reading it ties a view to `revision` too: a conversation is a plain
    /// class, so a change inside one (a message, a state) only bumps that.
    public var conversations: [Conversation] {
        _ = revision
        return conversationStore
    }
    @ObservationIgnored private var conversationStore: [Conversation] = []

    @ObservationIgnored private var notifying = false
    @ObservationIgnored private var notifyAgain = false

    private func touch() {
        revision &+= 1
        guard !observers.isEmpty else { return }
        // A change an observer makes re-enters here: it queues one more
        // round after this one instead of nesting.
        if notifying { notifyAgain = true; return }
        notifying = true
        repeat {
            notifyAgain = false
            for body in observers.values { body() }
        } while notifyAgain
        notifying = false
    }

    public func conversation(with contactID: String) -> Conversation? {
        conversations.first { $0.contactID == contactID }
    }

    func conversation(forTransport transportID: String) -> Conversation? {
        conversations.first { $0.transportID == transportID }
    }

    private func conversation(forGroup groupID: Hash32) -> Conversation? {
        conversations.first { $0.groupID == groupID }
    }

    public func contact(_ id: String) -> Contact? {
        contacts.first { $0.id == id }
    }

    public init() {}

    public static let shared: Client = {
        let client = Client()
        client.start()
        return client
    }()

    private var host: (any ConvoHost)? { ConvoServices.host }

    private func now() -> Double {
        #if canImport(FoundationEssentials)
        FoundationEssentials.Date().timeIntervalSince1970
        #else
        Foundation.Date().timeIntervalSince1970
        #endif
    }

    private func nowMS() -> UInt64 { UInt64(max(0, now() * 1000)) }

    /// The nodes' clock (unix ms) as their answers report it, advanced by
    /// this device's clock since; this device's clock until a node has
    /// answered.
    private var timeReading: (ms: UInt64, at: Double)?

    private func nodeTime() -> UInt64 {
        if let r = timeReading { return r.ms + UInt64(max(0, now() - r.at) * 1000) }
        return nowMS()
    }

    /// A node's clock, from whatever carried it: a health report, the
    /// node's info, or a fetch reply. Every signed request names a time
    /// the node checks against its own (§15, §19), and a device's clock
    /// can be minutes off, so the latest reading wins.
    private func noteTime(_ ms: UInt64) {
        timeReading = (ms, now())
    }

    // MARK: - Startup

    public var diagnostics: String {
        if ConvoServices.host == nil { return "waiting for a networking stack" }
        if !started { return "stack found, starting" }
        if selfID.isEmpty { return "loading identity" }
        return "identity \(selfID.prefix(6))"
    }

    public func startIfNeeded() { start() }

    private var started = false

    public func start() {
        guard !started, ConvoServices.host != nil else { return }
        started = true
        ConvoServices.onEvent = { [weak self] kind, payload in
            guard let self else { return }
            self.handle(kind: kind, payload: payload)
        }
        loadIdentity()
        loadCapabilities()
        loadServers()
    }

    // MARK: - Identity

    /// The identity is an Ed25519 key (§1): its 32-byte secret lives in
    /// the host's secret store (the keychain), derived from a recovery
    /// phrase the person saw once, or imported as a secret key. A seed the
    /// pairing-era app kept in plain storage is moved into the secret
    /// store; with nothing at all, the app asks the person to create or
    /// import one.
    private func loadIdentity() {
        guard let host else { return }
        ConvoServices.request({ [weak self] _, secret in
            guard let self else { return }
            if let data = Data(base64Encoded: secret), data.count == 32, let id = try? ConvoIdentity(seed: Array(data)) {
                self.adopt(id)
                return
            }
            ConvoServices.request({ [weak self] _, legacy in
                guard let self else { return }
                if let data = Data(base64Encoded: legacy), data.count == 32, let id = try? ConvoIdentity(seed: Array(data)) {
                    host.saveSecret(key: "identity", value: legacy)
                    host.save(key: "identity", value: "")
                    self.adopt(id)
                } else {
                    self.phase = .needsIdentity
                    self.touch()
                    // Opened from a handoff code before there is an identity.
                    ConvoServices.request({ [weak self] _, payload in
                        let trimmed = payload.hasPrefix("#") ? String(payload.dropFirst()) : payload
                        if trimmed.hasPrefix("d=") { self?.acceptHandoff(fragment: String(trimmed.dropFirst(2))) }
                    }, { host.openingHash(requestID: $0) })
                }
            }, { host.load(requestID: $0, key: "identity") })
        }, { host.loadSecret(requestID: $0, key: "identity") })
    }

    /// The identity's public key in hex, what other people add.
    public var identityKey: String { identity?.publicKey.hex ?? "" }

    /// A fresh 12-word recovery phrase for the person to save before it
    /// becomes the identity (`importIdentity(phrase:)` with these words).
    public func createIdentityPreview() -> [String] { Mnemonic.generate() }

    /// Creates a new identity in one step: a fresh phrase, kept in the
    /// secret store for Settings, and the key it derives (§1).
    @discardableResult
    public func createIdentity() -> [String] {
        let words = Mnemonic.generate()
        _ = importIdentity(phrase: words.joined(separator: " "))
        return words
    }

    /// Imports an identity: its recovery phrase (12 or 24 words) or its
    /// secret key in hex. Returns what went wrong.
    @discardableResult
    public func importIdentity(phrase: String) -> String? {
        guard let host else { return "no networking stack" }
        let words = phrase.lowercased().split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)
        let id: ConvoIdentity
        var savedPhrase: String?
        if words.count >= 12 {
            do { id = try ConvoIdentity(words: words) } catch Mnemonic.Failure.unknownWord(let w) { return "\"\(w)\" is not a recovery word" } catch { return "that is not a valid recovery phrase" }
            savedPhrase = words.joined(separator: " ")
        } else if words.count == 1, let bytes = [UInt8](hex: words[0]), bytes.count == 64 || bytes.count == 32,
                  let imported = try? ConvoIdentity(secretKey: bytes) {
            id = imported
        } else {
            return "enter a 12- or 24-word recovery phrase, or a secret key"
        }
        host.saveSecret(key: "identity", value: Data(id.key.seed).base64EncodedString())
        host.saveSecret(key: "phrase", value: savedPhrase ?? "")
        adopt(id)
        return nil
    }

    /// Puts text on the platform clipboard.
    public func copyToClipboard(_ text: String) { host?.copyText(text: text) }

    /// The recovery phrase, when this identity was made from one.
    public func recoveryPhrase(_ then: @escaping (String) -> Void) {
        guard let host else { then(""); return }
        ConvoServices.request({ _, payload in then(payload) }, { host.loadSecret(requestID: $0, key: "phrase") })
    }

    /// Forgets the identity on this device (the phrase is the way back).
    public func resetIdentity() {
        guard let host else { return }
        host.saveSecret(key: "identity", value: "")
        host.saveSecret(key: "phrase", value: "")
        host.save(key: "contacts", value: "")
        identity = nil
        selfID = ""
        conversationStore = []
        contacts = []
        phase = .needsIdentity
        touch()
    }

    private func adopt(_ id: ConvoIdentity) {
        identity = id
        storageKey = AtRest.key(identity: Data(id.key.seed))
        selfID = id.publicKey.hex
        selfFingerprint = Self.displayFingerprint(selfID)
        if phase == .needsIdentity { phase = .starting }
        guard let host else { return }
        ConvoServices.request({ [weak self] _, payload in
            guard let self else { return }
            self.nick = payload.isEmpty ? "peer-" + self.selfID.prefix(4) : payload
            self.loadContacts()
        }, { host.load(requestID: $0, key: "nick") })
        ConvoServices.request({ [weak self] _, payload in self?.pageBase = payload }, { host.pageURL(requestID: $0) })
        // The invite this identity last showed, before the address it opened with.
        ConvoServices.request({ [weak self] _, saved in
            self?.shownInviteSalt = Hash32(hex: saved)
            ConvoServices.request({ [weak self] _, payload in
                guard let self else { return }
                // A link the app was opened with (`open(url:)`) before the identity was loaded comes first.
                let opening = self.pendingOpening ?? payload
                self.pendingOpening = nil
                self.consumeOpeningHash(opening)
                self.identityReady = true
            }, { host.openingHash(requestID: $0) })
        }, { host.load(requestID: $0, key: "inviteSalt") })
    }

    /// The app was opened with a link: `p2prc://…#c=<invite>` (or `#d=` for a
    /// device handoff), or the web client's own `https://…#c=…`. Its
    /// fragment is taken as the web page takes its opening address; a link
    /// with none just brings the app forward (Applications' Open). Held until
    /// the identity is loaded when it comes first.
    public func open(url: String) {
        guard let marker = url.firstIndex(of: "#") else { return }
        let fragment = String(url[marker...])
        guard identityReady else { pendingOpening = fragment; return }
        consumeOpeningHash(fragment)
    }

    /// A link to open once the identity is loaded (`open(url:)`).
    private var pendingOpening: String?
    /// Whether the identity is loaded and its opening address consumed.
    private var identityReady = false

    public func setNick(_ name: String) {
        let trimmed = Self.trim(name)
        guard !trimmed.isEmpty else { return }
        nick = trimmed
        host?.save(key: "nick", value: trimmed)
        publishKeyPackage()
    }

    private static func trim(_ s: String) -> String {
        String(s.drop(while: \.isWhitespace).reversed().drop(while: \.isWhitespace).reversed())
    }

    /// The KeyPackage for a new handshake: `hpke_index` advances every
    /// `HPKE_ROTATION` of calendar time (§1; the key is derived, so no
    /// state is needed and every device of the identity agrees), and
    /// `not_after` is `KP_LIFETIME` out. Groups keep the index they were
    /// made with.
    private var hpkeIndex: UInt32 { UInt32(max(0, now()) / Parameters.Client.hpkeRotationSeconds) }
    private var keyPackage: KeyPackage? { identity?.keyPackage(name: nick, hpkeIndex: hpkeIndex) }

    // MARK: - Contacts and groups at rest
    //
    // Contacts persist as JSON; each group as one sealed record (genesis,
    // roster, the MLS commit secret and this member's sender generation)
    // and one sealed message log, under the at-rest key, so the host's
    // store (UserDefaults, localStorage, SharedPreferences) only ever holds
    // ciphertext.

    private struct GroupRecord: Codable {
        var genesis: String
        var roster: [String]
        var secret: String
        var generation: UInt32
        /// When this member last issued an Update commit (ms), for
        /// `MLS_UPDATE_INTERVAL` on the clock.
        var updatedAt: UInt64?
    }

    private func loadContacts() {
        guard let host else { return }
        ConvoServices.request({ [weak self] _, payload in
            guard let self else { return }
            if let data = payload.data(using: .utf8), let saved = try? JSONDecoder().decode([Contact].self, from: data) {
                self.contacts = saved
            }
            var remaining = self.contacts.filter(\.trusted).count
            if remaining == 0 { self.finishLoading() }
            for contact in self.contacts where contact.trusted {
                self.loadGroup(contact) { [weak self] in
                    remaining -= 1
                    if remaining == 0 { self?.finishLoading() }
                }
            }
        }, { host.load(requestID: $0, key: "contacts") })
    }

    private func finishLoading() {
        touch()
        if phase == .starting { phase = .idle }
        publishKeyPackage()
        pullLoop()
        pollLoop()
        commitLoop()
        for convo in conversations { beginReconnect(convo) }
    }

    private func saveContacts() {
        guard let data = try? JSONEncoder().encode(contacts) else { return }
        host?.save(key: "contacts", value: String(decoding: data, as: UTF8.self))
    }

    private func seal(_ data: Data) -> String? {
        guard let storageKey else { return nil }
        return try? AtRest.seal(data, key: storageKey)
    }

    private func open(_ record: String) -> Data? {
        guard let storageKey, !record.isEmpty else { return nil }
        return try? AtRest.open(record, key: storageKey)
    }

    private func saveGroup(_ convo: Conversation) {
        guard let host, let mls = convo.state.mlsState else { return }
        let record = GroupRecord(genesis: convo.state.genesis.borsh.hex, roster: convo.state.roster.map { $0.wire.hex },
                                 secret: mls.commitSecret.hex, generation: mls.ownGeneration, updatedAt: mls.updatedAt)
        guard let data = try? JSONEncoder().encode(record), let sealed = seal(data) else { return }
        host.save(key: "group:" + convo.groupID.hex, value: sealed)
    }

    private func saveMessages(_ convo: Conversation) {
        guard let host else { return }
        var w = BorshWriter()
        let wires = convo.state.dag.messages.values.map(\.wire)
        w.vec(wires) { w, m in w.vec(m) }
        w.vec(convo.state.dag.allAttestations) { w, a in w.vec(a.wire) }
        guard let sealed = seal(Data(w.bytes)) else { return }
        host.save(key: "messages:" + convo.groupID.hex, value: sealed)
    }

    /// The hosts' receipts (§14): what says a message reached a node.
    /// Kept so a relaunch knows what is still waiting for one.
    private func saveReceipts(_ convo: Conversation) {
        guard let host else { return }
        var w = BorshWriter()
        let wires = convo.state.receipts.values.flatMap { $0.values.map(\.wire) }
        w.vec(wires) { w, r in w.vec(r) }
        host.save(key: "receipts:" + convo.groupID.hex, value: Data(w.bytes).base64EncodedString())
    }

    private func saveCommitments(_ convo: Conversation) {
        guard let host else { return }
        var w = BorshWriter()
        w.vec(Array(convo.state.commitments.values)) { w, r in w.vec(r.borsh) }
        host.save(key: "commitments:" + convo.groupID.hex, value: Data(w.bytes).base64EncodedString())
    }

    private func loadGroup(_ contact: Contact, then: @escaping () -> Void) {
        guard let host, let identity else { then(); return }
        ConvoServices.request({ [weak self] _, payload in
            guard let self else { then(); return }
            defer { then() }
            guard let data = self.open(payload), let record = try? JSONDecoder().decode(GroupRecord.self, from: data),
                  let genesisBytes = Self.bytes(hex: record.genesis), let genesis = try? Genesis.decode(genesisBytes),
                  let secret = Self.bytes(hex: record.secret) else { return }
            let roster = record.roster.compactMap { Self.bytes(hex: $0) }.compactMap { try? KeyPackage.fromWire($0) }
            guard let state = try? GroupState(genesis: genesis, roster: roster, identity: identity, commitSecret: secret, ownGeneration: record.generation, updatedAt: record.updatedAt ?? 0) else { return }
            let convo = Conversation(contactID: contact.id, state: state)
            self.conversationStore.append(convo)
            ConvoServices.request({ _, since in if let t = Double(since), t > 0 { convo.syncingSince = t } },
                                  { host.load(requestID: $0, key: "syncing:" + convo.groupID.hex) })
            self.loadMessages(into: convo)
            if let ref = genesis.parent { self.loadArchive(into: convo, parent: ref.groupID) }
        }, { host.load(requestID: $0, key: "group:" + contact.groupID) })
    }

    /// The parent group's thread, from its saved record and messages, as
    /// the archived head of this conversation.
    private func loadArchive(into convo: Conversation, parent: Hash32) {
        guard let host, let identity else { return }
        ConvoServices.request({ [weak self] _, payload in
            guard let self, let data = self.open(payload), let record = try? JSONDecoder().decode(GroupRecord.self, from: data),
                  let genesisBytes = Self.bytes(hex: record.genesis), let genesis = try? Genesis.decode(genesisBytes),
                  let secret = Self.bytes(hex: record.secret) else { return }
            let roster = record.roster.compactMap { Self.bytes(hex: $0) }.compactMap { try? KeyPackage.fromWire($0) }
            guard let state = try? GroupState(genesis: genesis, roster: roster, identity: identity, commitSecret: secret, ownGeneration: record.generation, updatedAt: record.updatedAt ?? 0) else { return }
            let old = Conversation(contactID: convo.contactID, state: state)
            ConvoServices.request({ [weak self] _, payload in
                guard let self, let data = self.open(payload) else { return }
                var r = BorshReader(Array(data))
                guard let wires = try? r.vec({ try $0.vec() }) else { return }
                var pending = wires.compactMap { try? SignedMessage.fromWire($0) }
                var progress = true
                while progress, !pending.isEmpty {
                    progress = false
                    var next: [SignedMessage] = []
                    for m in pending { if (try? old.state.receive(m)) != nil { progress = true } else { next.append(m) } }
                    pending = next
                }
                self.refreshMessages(old)
                convo.archived = old.archived + old.messages.map { var m = $0; m.state = "archived"; return m }
                self.refreshMessages(convo)
            }, { host.load(requestID: $0, key: "messages:" + parent.hex) })
        }, { host.load(requestID: $0, key: "group:" + parent.hex) })
    }

    private func loadMessages(into convo: Conversation) {
        guard let host else { return }
        ConvoServices.request({ [weak self] _, payload in
            guard let self, let data = self.open(payload) else { return }
            var r = BorshReader(Array(data))
            guard let wires = try? r.vec({ try $0.vec() }) else { return }
            var pending = wires.compactMap { try? SignedMessage.fromWire($0) }
            var progress = true
            while progress, !pending.isEmpty {
                progress = false
                var next: [SignedMessage] = []
                for m in pending { if (try? convo.state.receive(m)) != nil { progress = true } else { next.append(m) } }
                pending = next
            }
            if let atts = try? r.vec({ try $0.vec() }) { for a in atts.compactMap({ try? SignedAttestation.fromWire($0) }) { convo.state.receive(a) } }
            ConvoServices.request({ [weak self] _, payload in
                guard let self else { return }
                if let data = Data(base64Encoded: payload) {
                    var cr = BorshReader(Array(data))
                    for ref in (try? cr.vec { try CommitmentRef.decode(try $0.vec()) }) ?? [] { convo.state.markCommitted(ref) }
                }
                ConvoServices.request({ [weak self] _, payload in
                    guard let self else { return }
                    if let data = Data(base64Encoded: payload) {
                        var rr = BorshReader(Array(data))
                        for receipt in ((try? rr.vec { try $0.vec() }) ?? []).compactMap({ try? Receipt.fromWire($0) }) where receipt.isValid {
                            convo.state.recordReceipt(receipt)
                        }
                    }
                    self.refreshMessages(convo)
                }, { host.load(requestID: $0, key: "receipts:" + convo.groupID.hex) })
            }, { host.load(requestID: $0, key: "commitments:" + convo.groupID.hex) })
        }, { host.load(requestID: $0, key: "messages:" + convo.groupID.hex) })
    }

    /// The screen's messages, from the group's canonical order.
    static let unreadableText = "(a message this device could not read)"

    private func refreshMessages(_ convo: Conversation) {
        let names = convo.state.roster.map(\.body.name)
        let ids = convo.state.roster.map { $0.body.identityPk.hex }
        let entries = convo.state.entries()
        // Reactions (kind 3) folded per target in canonical order: per
        // emoji, the authors whose latest reaction with it was not a removal.
        var reactionOrder: [Hash32: [String]] = [:]
        var reactionAuthors: [Hash32: [String: [UInt8]]] = [:]
        for e in entries where e.kind == .reaction {
            guard let r = e.reaction else { continue }
            if reactionAuthors[r.target]?[r.emoji] == nil { reactionOrder[r.target, default: []].append(r.emoji); reactionAuthors[r.target, default: [:]][r.emoji] = [] }
            reactionAuthors[r.target]?[r.emoji]?.removeAll { $0 == e.authorIdx }
            if !r.remove { reactionAuthors[r.target]?[r.emoji]?.append(e.authorIdx) }
        }
        let me = convo.state.memberIdx
        convo.messages = convo.archived + entries.compactMap { e in
            guard e.kind == .chat || e.kind == .attachment else { return nil }
            if e.kind == .attachment, e.attachment == nil { return nil }   // a payload this member cannot read
            let idx = Int(e.authorIdx)
            let mine = idx == Int(me)
            // §14: what we sent is "queued" until some host has receipted
            // it — the offline queue's visible edge — and "sent" from then.
            let held = !mine || convo.state.receipts.values.contains { $0[e.hash] != nil }
            let state: String = switch e.state {
            case .committed: "committed"; case .attested: "attested"; case .abandoned: "abandoned"
            default: held ? "sent" : "queued"
            }
            // A chat payload this member could not open shows as such
            // rather than as an empty bubble (a key or epoch mismatch is a
            // real problem, not silence).
            let text = e.attachment?.caption ?? e.text ?? (e.kind == .chat ? Self.unreadableText : "")
            var message = Message(id: e.hash.hex, sender: idx < ids.count ? ids[idx] : "", senderName: idx < names.count ? names[idx] : "",
                                  text: text, timestamp: Double(e.ts) / 1000, mine: mine, state: state)
            if let attachment = e.attachment {
                message.aspect = attachment.height > 0 ? Double(attachment.width) / Double(attachment.height) : 4.0 / 3.0
                message.image = convo.imageURLs[e.hash.hex]
                if message.image == nil { resolveAttachment(attachment, of: e.hash, in: convo) }
            }
            let summaries = (reactionOrder[e.hash] ?? []).compactMap { emoji -> ReactionSummary? in
                let authors = reactionAuthors[e.hash]?[emoji] ?? []
                return authors.isEmpty ? nil : ReactionSummary(emoji: emoji, count: authors.count, mine: authors.contains(me))
            }
            if !summaries.isEmpty { message.reactions = summaries }
            return message
        }
        handleControls(convo)
        let total = convo.state.dag.messages.count, done = convo.state.dag.messages.keys.filter { convo.state.isCommitted($0) }.count
        convo.chainStatus = total == 0 ? "nothing sent yet" : (done >= total ? "all \(total) committed" : "\(done) of \(total) committed")
        touch()
    }

    /// Control messages from the peer: a recovery fork's salt.
    private func handleControls(_ convo: Conversation) {
        for e in convo.state.entries() where e.kind == .control {
            guard let text = e.text, !convo.handledControls.contains(e.hash.hex) else { continue }
            convo.handledControls.insert(e.hash.hex)
            if text.hasPrefix("fork:"), e.authorIdx != convo.state.memberIdx, let salt = Hash32(hex: String(text.dropFirst("fork:".count))) {
                joinRecoveryFork(convo, salt: salt)
            }
        }
    }

    public func renameContact(_ contactID: String, to name: String) {
        guard let at = contacts.firstIndex(where: { $0.id == contactID }) else { return }
        let trimmed = Self.trim(name)
        contacts[at].name = trimmed.isEmpty ? defaultName(for: contactID) : trimmed
        saveContacts()
        if pendingNaming == contactID {
            pendingNaming = nil
            pairingVisible = false
            phase = .idle
        }
    }

    public func defaultName(for contactID: String) -> String {
        if let nick = conversation(with: contactID)?.peerNick, !nick.isEmpty { return nick }
        return "peer-" + contactID.prefix(4)
    }

    public func displayName(for contactID: String) -> String {
        if let contact = contact(contactID), !contact.name.isEmpty { return contact.name }
        return defaultName(for: contactID)
    }

    // MARK: - Capabilities

    private func loadCapabilities() {
        guard let host else { return }
        ConvoServices.request({ [weak self] _, payload in
            guard let self else { return }
            if let data = payload.data(using: .utf8), let found = try? JSONDecoder().decode(NetworkCapabilities.self, from: data) {
                self.capabilities = found
            }
        }, { host.capabilities(requestID: $0) })
    }

    // MARK: - Nodes (Part III §24)

    public static let coldStartSTUN = "stun:stun.l.google.com:19302"

    private var maintaining = false
    private var checking: Set<String> = []
    private var iceExpires: Double = 0

    private func loadServers() {
        guard let host else { return }
        ConvoServices.request({ [weak self] _, saved in
            guard let self, let host = self.host else { return }
            self.servers = ServerDirectory.decode(saved, limit: 10)
            self.loadNodeKeys()
            ConvoServices.request({ [weak self] _, seeds in
                guard let self else { return }
                for seed in seeds.split(separator: ",") { self.servers.add(String(seed), now: self.now()) }
                self.publishServers()
                self.pushIceServers()
                self.maintenanceLoop()
            }, { host.seeds(requestID: $0) })
        }, { host.load(requestID: $0, key: "servers") })
    }

    private func saveServers() {
        host?.save(key: "servers", value: servers.encoded())
        publishServers()
    }

    /// The nodes' keys by URL, kept with the directory: a launch without a
    /// network still knows which URL is which host, so the offline queue
    /// and the mailbox pull can try them as soon as one answers.
    private func saveNodeKeys() {
        let record = nodeKeys.mapValues(\.hex)
        guard let data = try? JSONEncoder().encode(record) else { return }
        host?.save(key: "nodekeys", value: String(decoding: data, as: UTF8.self))
    }

    private func loadNodeKeys() {
        guard let host else { return }
        ConvoServices.request({ [weak self] _, payload in
            guard let self, let data = payload.data(using: .utf8),
                  let record = try? JSONDecoder().decode([String: String].self, from: data) else { return }
            for (url, hex) in record where self.nodeKeys[url] == nil {
                if let key = Hash32(hex: hex) { self.nodeKeys[url] = key }
            }
        }, { host.load(requestID: $0, key: "nodekeys") })
    }

    private func publishServers() { signalingServers = servers.healthy }

    private var healthyNodeURLs: [String] { servers.healthy.map(\.url) }

    /// Healthy nodes whose key is known: the registry as this client sees
    /// it (no chain is attached).
    private var registry: [(url: String, key: Hash32)] {
        healthyNodeURLs.compactMap { url in nodeKeys[url].map { (url, $0) } }
    }

    /// A node's URL: a healthy node's from the registry; otherwise the
    /// last known URL of a node whose key we learned, so a group's hosts
    /// stay reachable through a transient outage (health checks back off
    /// for minutes; a post that succeeds re-checks the node at once).
    private func url(forNode key: Hash32) -> String? {
        if let healthy = registry.first(where: { $0.key == key })?.url { return healthy }
        return nodeKeys.first { $0.value == key && servers.servers[$0.key] != nil }?.key
    }

    /// A node answered: if the directory has it failing, re-check it now
    /// rather than after the backoff.
    private func noteReachable(_ url: String) {
        guard let known = servers.servers[url], !known.isHealthy else { return }
        healthCheck(url) { _ in }
    }

    /// `RV(key, k_rv)` over the registry, as node URLs; every healthy node
    /// when keys are still unknown.
    private func rendezvousURLs(for key: Hash32) -> [String] {
        let reg = registry
        guard !reg.isEmpty else { return healthyNodeURLs }
        return Rendezvous.select(key: key, from: reg.map(\.key), count: Parameters.Client.rendezvousSetSize).compactMap { url(forNode: $0) }
    }

    private func maintenanceLoop() {
        guard let host, !maintaining else { return }
        maintaining = true
        func tick() {
            ConvoServices.request({ [weak self] _, _ in
                guard let self else { return }
                self.runHealthChecks()
                self.runDiscovery()
                if self.iceExpires - 120 < self.now() { self.pushIceServers() }
                tick()
            }, { host.delay(requestID: $0, ms: 60_000) })
        }
        runHealthChecks()
        runDiscovery()
        tick()
    }

    /// `CONVO_DEBUG_NET=1`: the directory's decisions on stdout (health
    /// checks, backoff, the offline queue), for the test harness.
    private static let netTrace = ProcessInfo.processInfo.environment["CONVO_DEBUG_NET"] == "1"
    private func trace(_ line: @autoclosure () -> String) { if Self.netTrace { print("NET " + line()) } }

    private func runHealthChecks() {
        let due = servers.due(now: now())
        trace("health checks due=\(due.count) of \(servers.servers.count) healthy=\(healthyNodeURLs.count) keys=\(nodeKeys.count)")
        for server in due { healthCheck(server.url) { _ in } }
        for url in healthyNodeURLs where nodeKeys[url] == nil { fetchNodeKey(url) }
    }

    /// GET /health; records the outcome; learns the node's key.
    private func healthCheck(_ url: String, then: @escaping (HealthReport?) -> Void) {
        guard let host, !checking.contains(url) else { return }
        checking.insert(url)
        ConvoServices.request({ [weak self] ok, body in
            guard let self else { return }
            self.checking.remove(url)
            let report = ok ? body.data(using: .utf8).flatMap { try? JSONDecoder().decode(HealthReport.self, from: $0) } : nil
            self.trace("health \(url) ok=\(ok) report=\(report != nil)")
            if let report, report.ok, report.kind == "node" || report.kind == "signaling" {
                self.servers.recordHealthy(url, report: report, now: self.now())
                self.noteTime(UInt64(max(0, report.now) * 1000))
                if self.nodeKeys[url] == nil { self.fetchNodeKey(url) }
            } else {
                _ = self.servers.recordFailure(url, now: self.now())
            }
            self.saveServers()
            then(report)
        }, { host.httpGet(requestID: $0, url: url + NodeAPI.health) })
    }

    private func fetchNodeKey(_ url: String) {
        guard let host else { return }
        ConvoServices.request({ [weak self] ok, body in
            guard let self, ok, let data = body.data(using: .utf8),
                  let info = try? JSONDecoder().decode(NodeInfo.self, from: data), let key = info.publicKey else { return }
            self.nodeKeys[url] = key
            self.saveNodeKeys()
            if let ms = info.now { self.noteTime(ms) }
        }, { host.httpGet(requestID: $0, url: url + NodeAPI.info) })
    }

    private var walk: DiscoveryWalk?

    private func runDiscovery() {
        guard walk == nil, servers.shouldDiscover(now: now()) else { return }
        servers.markDiscovery(now: now())
        walk = DiscoveryWalk(from: servers, seeds: [])
        discoverNext()
    }

    private func discoverNext() {
        guard let host, var walk else { return }
        guard !servers.satisfied, let url = walk.next() else {
            self.walk = nil
            saveServers()
            return
        }
        self.walk = walk
        ConvoServices.request({ [weak self] ok, body in
            guard let self, var walk = self.walk else { return }
            if ok, let data = body.data(using: .utf8), let list = try? JSONDecoder().decode(ServerList.self, from: data) {
                walk.absorb(list, from: url)
                self.walk = walk
                var fresh: [String] = []
                for learned in walk.learned where self.servers.add(learned, now: self.now()) { fresh.append(learned) }
                var pending = fresh.count
                guard pending > 0 else { self.discoverNext(); return }
                for learned in fresh {
                    self.healthCheck(learned) { [weak self] _ in
                        pending -= 1
                        if pending == 0 { self?.discoverNext() }
                    }
                }
                return
            }
            self.discoverNext()
        }, { host.httpGet(requestID: $0, url: url + "/servers") })
    }

    public func advertiseServer(_ raw: String) {
        guard let host, let url = ServerDirectory.normalize(raw) else {
            status = "that is not an http(s) URL"
            return
        }
        servers.add(url, now: now())
        saveServers()
        healthCheck(url) { [weak self] report in
            guard let self else { return }
            self.status = report == nil ? "\(url) did not answer /health" : "added \(url)"
            if report != nil { self.publishKeyPackage() }
        }
        guard let body = try? JSONEncoder().encode(Advertisement(knownSignalingServers: [url])) else { return }
        let json = String(decoding: body, as: UTF8.self)
        for server in healthyNodeURLs where server != url {
            ConvoServices.request({ _, _ in }, { host.httpPost(requestID: $0, url: server + "/servers", body: json) })
        }
    }

    public func forgetServer(_ url: String) {
        servers.remove(url)
        nodeKeys[url] = nil
        saveServers()
    }

    private func pushIceServers() { withICE(force: true) {} }

    private static func iceJSON(_ servers: [ICEServer]) -> String {
        (try? JSONEncoder().encode(servers)).map { String(decoding: $0, as: UTF8.self) } ?? "[]"
    }

    /// Runs `then` with a fresh ICE list when the current one is stale.
    private func withICE(force: Bool = false, _ then: @escaping () -> Void) {
        guard let host else { then(); return }
        guard force || iceExpires - 60 < now() else { then(); return }
        let candidates = servers.healthy.sorted { $0.turn && !$1.turn }
        guard let server = candidates.first else {
            host.setIceServers(json: Self.iceJSON([ICEServer(urls: [Self.coldStartSTUN])]))
            then()
            return
        }
        ConvoServices.request({ [weak self] ok, body in
            guard let self else { return }
            if ok, let data = body.data(using: .utf8), let answer = try? JSONDecoder().decode(ICEAnswer.self, from: data), !answer.iceServers.isEmpty {
                self.iceExpires = self.now() + Double(max(answer.ttl, 300))
                host.setIceServers(json: Self.iceJSON(answer.iceServers + [ICEServer(urls: [Self.coldStartSTUN])]))
            } else if self.iceExpires == 0 {
                host.setIceServers(json: Self.iceJSON([ICEServer(urls: [Self.coldStartSTUN])]))
            }
            then()
        }, { host.httpGet(requestID: $0, url: server.url + NodeAPI.ice + "?for=" + self.selfID) })
    }

    // MARK: - Byte HTTP to nodes

    /// A member-only GET (§19), signed with the group key: the signature
    /// covers the request target (the URL's path and query) and the time
    /// on the nodes' clock.
    private func getBytesSigned(_ url: String, key: SigningKey, _ then: @escaping (Bool, [UInt8]) -> Void) {
        guard let host, let start = url.firstRange(of: "/v1/") else { then(false, []); return }
        let auth = NodeAPI.getAuth(key: key, pathAndQuery: String(url[start.lowerBound...]), time: nodeTime())
        ConvoServices.request({ ok, payload in
            then(ok, ok ? (Data(base64Encoded: payload).map(Array.init) ?? []) : [])
        }, { host.httpGetBytesSigned(requestID: $0, url: url, auth: auth) })
    }

    private func getBytes(_ url: String, _ then: @escaping (Bool, [UInt8]) -> Void) {
        guard let host else { then(false, []); return }
        ConvoServices.request({ ok, payload in
            then(ok, ok ? (Data(base64Encoded: payload).map(Array.init) ?? []) : [])
        }, { host.httpGetBytes(requestID: $0, url: url) })
    }

    private func postBytes(_ url: String, _ bytes: [UInt8], _ then: @escaping (Bool, [UInt8]) -> Void) {
        guard let host else { then(false, []); return }
        ConvoServices.request({ ok, payload in
            then(ok, ok ? (Data(base64Encoded: payload).map(Array.init) ?? []) : [])
        }, { host.httpPostBytes(requestID: $0, url: url, body64: Data(bytes).base64EncodedString()) })
    }

    // MARK: - KeyPackages (§2, §13.1)

    private var publishedKeyPackageTo: Set<String> = []

    /// This identity's KeyPackage to `RV(id_pk, k_rv)` (every healthy node
    /// until keys are known), once per node per name.
    private func publishKeyPackage() {
        guard let identity, let kp = keyPackage else { return }
        let stamp = nick + "@" + String(hpkeIndex)
        for url in rendezvousURLs(for: identity.publicKey) where !publishedKeyPackageTo.contains(url + stamp) {
            postBytes(url + NodeAPI.keyPackage(identity.publicKey), kp.wire) { [weak self] ok, _ in
                if ok { self?.publishedKeyPackageTo.insert(url + stamp) }
            }
        }
    }

    private func fetchKeyPackage(_ id: Hash32, then: @escaping (KeyPackage?) -> Void) {
        var urls = rendezvousURLs(for: id)
        for u in healthyNodeURLs where !urls.contains(u) { urls.append(u) }
        func next() {
            guard !urls.isEmpty else { then(nil); return }
            let url = urls.removeFirst()
            getBytes(url + NodeAPI.keyPackage(id)) { ok, bytes in
                if ok, let kp = try? KeyPackage.fromWire(bytes), kp.body.identityPk == id { then(kp) } else { next() }
            }
        }
        next()
    }

    // MARK: - Another device (a handoff)

    /// What a new device needs to be this identity: the seed, the name,
    /// the contacts and every conversation's record (its genesis, roster
    /// and MLS secret; the messages come back from the hosts). Sealed under
    /// a key only the code carries and left in a rendezvous box (§20) for
    /// ten minutes, in pieces that fit a box's blob.
    private struct Handoff: Codable {
        var seed: String
        var nick: String
        var contacts: [Contact]
        var groups: [String: GroupRecord]
    }

    private var handoffGeneration = 0
    private static let handoffPieceBytes = 11_000

    /// Shows the code another device scans to become this identity.
    public func presentHandoff() {
        guard let host, let identity else { return }
        let nodes = Array(healthyNodeURLs.prefix(3))
        guard !nodes.isEmpty else { handoffStatus = Self.noServerStatus; return }
        var groups: [String: GroupRecord] = [:]
        for convo in conversations {
            guard let mls = convo.state.mlsState else { continue }
            groups[convo.groupID.hex] = GroupRecord(genesis: convo.state.genesis.borsh.hex, roster: convo.state.roster.map { $0.wire.hex },
                                                    secret: mls.commitSecret.hex, generation: mls.ownGeneration, updatedAt: mls.updatedAt)
        }
        let handoff = Handoff(seed: Data(identity.key.seed).base64EncodedString(), nick: nick, contacts: contacts, groups: groups)
        guard let json = try? JSONEncoder().encode(handoff), let (key, sealed) = try? BlobSeal.seal(Array(json)) else { return }
        let box = (0..<16).map { _ in UInt8.random(in: 0...255) }.hex
        let pieces = stride(from: 0, to: sealed.count, by: Self.handoffPieceBytes).map { Array(sealed[$0..<min($0 + Self.handoffPieceBytes, sealed.count)]) }
        guard pieces.count <= 32 else { handoffStatus = "too much to hand off at once"; return }
        for (i, piece) in pieces.enumerated() { drop([UInt8(i), UInt8(pieces.count)] + piece, box: box, urls: nodes) }
        let fragment = box + "." + Self.base64URL(Data(key)) + "." + Self.base64URL(Data(nodes.joined(separator: "|").utf8))
        handoffLink = linkBase + "#d=" + fragment
        host.setHash(value: "d=" + fragment)
        handoffGeneration += 1
        let generation = handoffGeneration
        ConvoServices.request({ [weak self] ok, payload in
            guard let self, ok, self.handoffGeneration == generation else { return }
            self.handoffQRImage = payload
        }, { host.qrImage(requestID: $0, text: self.handoffLink) })
        handoffStatus = "On the new device, choose \"Use another device\" and scan this. It works for ten minutes."
    }

    public func endHandoff() {
        handoffGeneration += 1
        if !handoffLink.isEmpty { host?.setHash(value: "") }
        handoffLink = ""
        handoffQRImage = ""
        handoffStatus = ""
    }

    public func shareHandoff() {
        guard !handoffLink.isEmpty else { return }
        host?.share(text: handoffLink)
    }

    /// `#d=<box>.<key>.<nodes>`, from the other device's code, or a whole
    /// link pasted: takes the handoff up and becomes that identity.
    public func acceptHandoff(fragment raw: String) {
        let fragment = raw.firstRange(of: "#d=").map { String(raw[$0.upperBound...]) } ?? raw
        guard identity == nil else { handoffStatus = "Sign out of this device first."; return }
        let parts = fragment.split(separator: ".", maxSplits: 2)
        guard parts.count == 3, parts[0].count == 32, let keyData = Self.fromBase64URL(String(parts[1])), keyData.count == 32,
              let nodesData = Self.fromBase64URL(String(parts[2])) else {
            handoffStatus = "That isn't a P2PRC device code."
            return
        }
        let box = String(parts[0])
        let key = Array(keyData)
        let urls = String(decoding: nodesData, as: UTF8.self).split(separator: "|").compactMap { ServerDirectory.normalize(String($0)) }
        for url in urls where servers.add(url, now: now()) { healthCheck(url) { _ in } }
        handoffStatus = "Fetching from your other device…"
        handoffGeneration += 1
        let generation = handoffGeneration
        var pieces: [UInt8: [UInt8]] = [:]
        var expected: Int?
        var remaining = urls.count
        var finished = false
        for url in urls {
            take(box: box, url: url, each: { frame in
                guard frame.count > 2 else { return }
                pieces[frame[0]] = Array(frame[2...])
                expected = Int(frame[1])
            }, done: { [weak self] in
                guard let self, self.handoffGeneration == generation, !finished else { return }
                remaining -= 1
                if let expected, pieces.count == expected {
                    finished = true
                    let sealed = (0..<expected).flatMap { pieces[UInt8($0)] ?? [] }
                    guard let json = try? BlobSeal.open(sealed, key: key),
                          let handoff = try? JSONDecoder().decode(Handoff.self, from: Data(json)) else {
                        self.handoffStatus = "The code didn't match what was waiting. Show a fresh one."
                        return
                    }
                    self.install(handoff)
                } else if remaining == 0 {
                    self.handoffStatus = "Nothing is waiting at the nodes. Show the code again on the other device."
                }
            })
        }
        if urls.isEmpty { handoffStatus = Self.noServerStatus }
    }

    private func install(_ handoff: Handoff) {
        guard let host, let data = Data(base64Encoded: handoff.seed), data.count == 32, let id = try? ConvoIdentity(seed: Array(data)) else {
            handoffStatus = "The handoff was unreadable."
            return
        }
        host.saveSecret(key: "identity", value: handoff.seed)
        host.saveSecret(key: "phrase", value: "")
        storageKey = AtRest.key(identity: data)
        for (groupID, record) in handoff.groups {
            guard let json = try? JSONEncoder().encode(record), let sealed = seal(json) else { continue }
            host.save(key: "group:" + groupID, value: sealed)
        }
        if let contacts = try? JSONEncoder().encode(handoff.contacts) { host.save(key: "contacts", value: String(decoding: contacts, as: UTF8.self)) }
        host.save(key: "nick", value: handoff.nick)
        handoffStatus = ""
        adopt(id)
    }

    // MARK: - Rendezvous boxes (Part III §20)

    private func drop(_ frame: [UInt8], box: String, urls: [String]) {
        guard let host else { return }
        let text = Data(frame).base64EncodedString()
        for url in urls {
            ConvoServices.request({ _, _ in }, { host.httpPost(requestID: $0, url: url + NodeAPI.rendezvous(box), body: text) })
        }
    }

    /// Takes every waiting frame in `box` at `url`.
    private func take(box: String, url: String, each: @escaping ([UInt8]) -> Void, done: @escaping () -> Void) {
        guard let host else { done(); return }
        ConvoServices.request({ [weak self] ok, payload in
            guard let self else { done(); return }
            if ok, let bytes = Data(base64Encoded: payload) {
                each(Array(bytes))
                self.take(box: box, url: url, each: each, done: done)
            } else { done() }
        }, { host.httpGet(requestID: $0, url: url + NodeAPI.rendezvous(box)) })
    }

    /// One poll pass over every box addressed to this identity: the
    /// handshake in flight and each group's signaling box, at every
    /// healthy node. Runs every few seconds while anything wants it.
    private var polling = false
    private func pollLoop() {
        guard let host, !polling else { return }
        polling = true
        func tick() {
            pollOnce()
            ConvoServices.request({ [weak self] _, _ in
                guard let self else { return }
                if self.wantsPolling { tick() } else { self.polling = false }
            }, { host.delay(requestID: $0, ms: 2_500) })
        }
        tick()
    }

    private var wantsPolling: Bool {
        phase == .inviting || phase == .joining || conversations.contains { !$0.connected || $0.forkSalt != nil }
    }

    private func pollOnce() {
        guard let identity else { return }
        let me = identity.publicKey
        var boxes: [(box: String, handler: ([UInt8]) -> Void)] = []
        if let salt = handshakeSalt {
            boxes.append((NodeAPI.handshakeBox(salt: salt, recipient: me), { [weak self] f in self?.handshakeFrame(f) }))
        }
        for convo in conversations where !convo.connected {
            boxes.append((NodeAPI.handshakeBox(salt: convo.groupID, recipient: me), { [weak self] f in self?.signalingFrame(f, in: convo) }))
        }
        for convo in conversations {
            if let salt = convo.forkSalt {
                boxes.append((NodeAPI.handshakeBox(salt: salt, recipient: me), { [weak self] f in self?.forkFrame(f, in: convo) }))
            }
        }
        for url in healthyNodeURLs {
            for (box, handler) in boxes { take(box: box, url: url, each: handler, done: {}) }
        }
    }

    // MARK: - Pairing = the genesis handshake (§2)
    //
    // The invite is the inviter's identity, a fresh salt, and where to meet
    // (node URLs). Whoever scans it becomes the group's creator: they fetch
    // the inviter's KeyPackage, run the MLS handshake through the nodes'
    // rendezvous boxes under that salt, and both end up with the group. The
    // salt is the secret the QR carries; presenting it proves the screen
    // was seen, so no typed code is needed.

    private var handshakeSalt: Hash32?
    /// The salt of the invite this identity last showed (kept across a
    /// reload), the only one of its own it shows again.
    private var shownInviteSalt: Hash32?
    private var joiner: HandshakeJoiner?
    private var creator: HandshakeCreator?
    private var inviteGeneration = 0
    private var pairingContactID: String?

    private var linkBase: String {
        if !pageBase.isEmpty { return pageBase }
        if let site = servers.healthy.first?.site { return site.hasSuffix("/") ? site : site + "/" }
        return ""
    }

    /// How many times an invite has waited three seconds for a node.
    private var inviteWaits = 0

    public func invite() {
        guard let host, let identity else { return }
        // No node confirmed yet (a fresh launch, a slow first connection):
        // check them all again and try for a while before giving up.
        guard !healthyNodeURLs.isEmpty else {
            if inviteWaits < 8 {
                inviteWaits += 1
                phase = .inviting
                status = "Looking for a node…"
                for url in servers.servers.keys { healthCheck(url) { _ in } }
                ConvoServices.request({ [weak self] _, _ in
                    guard let self, self.phase == .inviting, self.inviteLink.isEmpty else { return }
                    self.invite()
                }, { host.delay(requestID: $0, ms: 3_000) })
                return
            }
            inviteWaits = 0
            phase = .failed(Self.noServerStatus)
            return
        }
        inviteWaits = 0
        let salt = Hash32(SymmetricKey(size: .bits256).withUnsafeBytes { Array($0) })
        showInvite(salt: salt, nodes: Array(healthyNodeURLs.prefix(3)))
    }

    /// The invite is answered or given up: not shown again after a reload.
    private func forgetShownInvite() {
        shownInviteSalt = nil
        host?.save(key: "inviteSalt", value: "")
    }

    /// The invite for `salt`, shown and waited on: a new one, or our own
    /// found in the address again after a reload.
    private func showInvite(salt: Hash32, nodes: [String]) {
        guard let host, let identity else { return }
        phase = .inviting
        inviteGeneration += 1
        handshakeSalt = salt
        shownInviteSalt = salt
        host.save(key: "inviteSalt", value: salt.hex)
        let j = HandshakeJoiner(identity: identity)
        j.minTotalHosts = 1
        j.maxTotalHosts = Parameters.Client.maxTotalHosts
        joiner = j
        let fragment = Self.base64URL(Data(identity.publicKey.bytes)) + "." + Self.base64URL(Data(salt.bytes))
            + "." + Self.base64URL(Data(nodes.joined(separator: "|").utf8))
        inviteLink = linkBase + "#c=" + fragment
        host.setHash(value: "c=" + fragment)
        host.drawQR(elementID: "invite-qr", text: inviteLink)
        let generation = inviteGeneration
        renderQR(inviteLink, generation: generation) { $0.inviteQRImage = $1 }
        status = "have them scan this"
        publishKeyPackage()
        pollLoop()
    }

    static let noServerStatus = "No node is reachable from here. Check the connection, or add one in Settings."

    /// `#c=<id_pk>.<salt>.<nodes>`: someone invited us. We create the group.
    private func consumeOpeningHash(_ hash: String) {
        let trimmed = hash.hasPrefix("#") ? String(hash.dropFirst()) : hash
        if trimmed.hasPrefix("c=") {
            pairingVisible = true
            acceptInvite(fragment: String(trimmed.dropFirst(2)))
            return
        }
        if trimmed.hasPrefix("d=") {
            acceptHandoff(fragment: String(trimmed.dropFirst(2)))
            return
        }
        if phase == .starting { phase = .idle }
        status = "ready"
    }

    public func acceptInvite(fragment: String) {
        let parts = fragment.split(separator: ".", maxSplits: 2)
        guard parts.count == 3, let idData = Self.fromBase64URL(String(parts[0])), idData.count == 32,
              let saltData = Self.fromBase64URL(String(parts[1])), saltData.count == 32,
              let nodesData = Self.fromBase64URL(String(parts[2])) else {
            phase = .failed("that code isn't a P2PRC invite")
            return
        }
        let inviter = Hash32(Array(idData))
        let salt = Hash32(Array(saltData))
        // Our own invite, still in the address after a reload (or a Home
        // Screen app relaunched): show it again and keep waiting on it, rather
        // than pair with ourselves. The key package is the identity's own, so
        // whoever scanned it can still answer.
        // Our own key in a link: only an invite this client made (its salt
        // kept) is shown again, with the nodes we reach, never the link's.
        // Anything else (a link someone forged with our key, a salt they
        // know and their nodes) gets a new invite instead.
        if inviter == identity?.publicKey {
            if salt == shownInviteSalt {
                // Just after a reload no node may have answered yet: then the ones we know.
                let ours = healthyNodeURLs.isEmpty ? servers.servers.keys.sorted() : healthyNodeURLs
                showInvite(salt: salt, nodes: Array(ours.prefix(3)))
            } else {
                invite()
            }
            return
        }
        phase = .joining
        handshakeSalt = salt
        peerFingerprint = Self.displayFingerprint(inviter.hex)
        status = "connecting…"
        for raw in String(decoding: nodesData, as: UTF8.self).split(separator: "|") {
            if let url = ServerDirectory.normalize(String(raw)), servers.add(url, now: now()) { healthCheck(url) { _ in } }
        }
        publishKeyPackage()
        // Their KeyPackage may need the invite's nodes to come up first.
        var attempts = 0
        func tryStart() {
            guard let host = self.host, self.phase == .joining, self.handshakeSalt == salt else { return }
            self.fetchKeyPackage(inviter) { [weak self] kp in
                guard let self, self.phase == .joining else { return }
                if let kp { self.startCreation(with: kp, salt: salt); return }
                attempts += 1
                guard attempts < 15 else { self.phase = .failed("couldn't find their KeyPackage at any node"); return }
                ConvoServices.request({ _, _ in tryStart() }, { host.delay(requestID: $0, ms: 2_000) })
            }
        }
        tryStart()
    }

    private func startCreation(with inviterPackage: KeyPackage, salt: Hash32) {
        guard let identity, let mine = keyPackage else { return }
        let hosts = registry.map(\.key)
        guard !hosts.isEmpty else {
            phase = .failed("no node has answered yet; try again in a moment")
            return
        }
        let proposal = HandshakeFrame.Proposal.defaults(members: 2, homeNodes: Array(hosts.prefix(Parameters.Client.maxTotalHosts)))
        do {
            let c = try HandshakeCreator(identity: identity, roster: [mine, inviterPackage], proposal: proposal, salt: salt)
            creator = c
            drop(c.invite(), box: NodeAPI.handshakeBox(salt: salt, recipient: inviterPackage.body.identityPk), urls: healthyNodeURLs)
            status = "waiting for them…"
            pollLoop()
        } catch {
            phase = .failed("couldn't start the group: \(error)")
        }
    }

    /// A frame in this identity's handshake box: an invite (we were shown
    /// the QR) or an announce (we scanned it).
    private func handshakeFrame(_ frame: [UInt8]) {
        guard let salt = handshakeSalt else { return }
        if let c = creator, phase == .joining {
            guard let genesisFrame = try? c.receive(frame) else { return }
            drop(genesisFrame, box: NodeAPI.handshakeBox(salt: salt, recipient: c.roster[1].body.identityPk), urls: healthyNodeURLs)
            if let state = try? c.session() {
                adopt(state, peer: c.roster[1])
                if let convo = conversation(with: c.roster[1].body.identityPk.hex) {
                    convo.carrySigs = c.carrySigs
                    publishGenesis(convo)
                }
            }
            return
        }
        if let j = joiner, phase == .inviting {
            guard let reply = try? j.receive(frame) else {
                if j.genesis != nil, let state = try? j.session(), let peer = j.roster.first { adopt(state, peer: peer) }
                return
            }
            if let creatorID = j.roster.first?.body.identityPk {
                drop(reply, box: NodeAPI.handshakeBox(salt: salt, recipient: creatorID), urls: healthyNodeURLs)
                peerFingerprint = Self.displayFingerprint(creatorID.hex)
                status = "connecting…"
            }
        }
    }

    /// The handshake produced a group: keep it, and give the person a
    /// chance to name who they just paired with.
    private func adopt(_ state: GroupState, peer: KeyPackage) {
        let contactID = peer.body.identityPk.hex
        if let existing = conversation(with: contactID) {
            conversationStore.removeAll { $0 === existing }
        }
        let convo = Conversation(contactID: contactID, state: state)
        conversationStore.append(convo)
        if let at = contacts.firstIndex(where: { $0.id == contactID }) {
            contacts[at].groupID = state.groupID.hex
            contacts[at].trusted = true
        } else {
            contacts.append(Contact(id: contactID, name: "", groupID: state.groupID.hex, trusted: true))
        }
        saveContacts()
        saveGroup(convo)
        lastPairedContact = contactID
        pairingContactID = contactID
        handshakeSalt = nil
        forgetShownInvite()
        creator = nil
        joiner = nil
        inviteLink = ""
        inviteQRImage = ""
        host?.setHash(value: "")
        host?.drawQR(elementID: "invite-qr", text: "")
        phase = .idle
        touch()
        if contact(contactID)?.name.isEmpty == true { pendingNaming = contactID } else { pairingVisible = false }
        status = "paired"
        beginReconnect(convo)
        pullLoop()
        commitLoop()
    }

    // MARK: - Commitments and attestations (§5–§7, §16a)
    //
    // Home nodes hold the genesis record, receipt every item into a batch
    // they will commit, and serve the commitment proofs; the app resolves
    // each against the witnessed checkpoint it carries (§6, §11) and shows
    // each message as sent, attested or committed.

    /// `POST /v1/groups/<id>/genesis` at every home node (§13), the
    /// creator's side; repeated with more carries as they arrive.
    private func publishGenesis(_ convo: Conversation) {
        let wire = GenesisRecord(genesis: convo.state.genesis, carrySigs: convo.carrySigs).wire
        for node in convo.state.genesis.homeNodes {
            guard let url = url(forNode: node), !convo.genesisPublished.contains(url + "\(convo.carrySigs.count)") else { continue }
            postBytes(url + NodeAPI.genesis(convo.groupID), wire) { [weak self] ok, _ in
                guard let self, ok else { return }
                convo.genesisPublished.insert(url + "\(convo.carrySigs.count)")
                self.touch()
            }
        }
    }

    private var committing = false

    /// Every ten seconds: each group's commitments resolved, the cadence
    /// rule applied, the genesis record at every home node.
    private func commitLoop() {
        guard let host, !committing else { return }
        committing = true
        func tick() {
            for convo in conversations { syncCommitments(convo); publishGenesis(convo) }
            ConvoServices.request({ [weak self] _, _ in
                guard let self else { return }
                if self.conversations.isEmpty { self.committing = false } else { tick() }
            }, { host.delay(requestID: $0, ms: 10_000) })
        }
        tick()
    }

    /// Asks the hosts for a `CommitmentRef` of every item not yet
    /// committed, then attests when the cadence says so.
    private func syncCommitments(_ convo: Conversation) {
        let dag = convo.state.dag
        let held = Set(dag.messages.keys).union(dag.allAttestations.map(\.itemHash)).filter { !dag.committed.contains($0) }
        let hosts = convo.state.hosts.compactMap { node in url(forNode: node).map { (node, $0) } }
        for item in held.prefix(64) {
            for (node, url) in hosts {
                getBytesSigned(url + NodeAPI.commitment(item), key: convo.state.groupKey) { [weak self] ok, bytes in
                    guard let self, ok, let ref = try? CommitmentRef.decode(bytes), ref.nodePk == node, ref.itemHash == item,
                          !convo.state.isCommitted(item) else { return }
                    // The ref carries the checkpoint it resolves against (§6).
                    guard ref.resolves() else { return }
                    convo.state.markCommitted(ref)
                    self.refreshMessages(convo)
                    self.saveCommitments(convo)
                }
            }
        }
        if convo.state.attestationDue(now: nodeTime()) { attest(convo) }
    }

    /// Signs the head and hands the attestation to every host (§5); the
    /// nodes commit it like any item.
    private func attest(_ convo: Conversation) {
        guard let signed = convo.state.attest() else { return }
        convo.state.noteAttested(at: nodeTime())
        for url in hostURLs(convo) {
            postBytes(url + NodeAPI.item(convo.groupID, kind: .attestation), signed.wire) { ok, bytes in
                guard ok, let receipt = try? Receipt.fromWire(bytes), receipt.isValid, receipt.body.itemHash == signed.itemHash else { return }
                convo.state.recordReceipt(receipt)
            }
        }
        if convo.connected { host?.sendFrame(peer: convo.transportID, text: Data([SyncFrame.attestation] + signed.wire).base64EncodedString()) }
        refreshMessages(convo)
        saveMessages(convo)
    }

    /// A signed message to the peer when connected and to every host.
    private func publish(_ signed: SignedMessage, in convo: Conversation) {
        guard let host else { return }
        if convo.connected {
            host.sendFrame(peer: convo.transportID, text: Data([SyncFrame.message] + signed.wire).base64EncodedString())
        }
        let digest = Hashing.sha256(signed.wire)
        for url in hostURLs(convo) {
            postBytes(url + NodeAPI.item(convo.groupID, kind: .message), signed.wire) { [weak self] ok, bytes in
                guard let self, ok, let receipt = try? Receipt.fromWire(bytes), receipt.isValid,
                      receipt.body.itemHash == signed.hash, receipt.body.contentDigest == digest else { return }
                let first = !convo.state.receipts.values.contains { $0[signed.hash] != nil }
                convo.state.recordReceipt(receipt)
                self.saveReceipts(convo)
                self.noteReachable(url)
                if first { self.refreshMessages(convo) }
            }
        }
    }

    /// The offline queue (§10, §14): our messages no host has receipted
    /// yet — composed with no node reachable, or posted while one was
    /// down — go out again on every pull tick until each host holds them.
    /// A host that already has the bytes answers with the same receipt.
    private static let republishBatch = 16

    private func republishQueued(_ convo: Conversation) {
        let hosts = convo.state.hosts.compactMap { node in url(forNode: node).map { (node, $0) } }
        trace("queue \(convo.groupID.hex.prefix(8)) hosts=\(hosts.count) of \(convo.state.hosts.count)")
        guard !hosts.isEmpty else { return }
        let mine = convo.state.dag.messages.values
            .filter { $0.message.authorIdx == convo.state.memberIdx && $0.message.kind == ConvoCore.Message.Kind.chat.rawValue }
            .sorted { $0.message.seq < $1.message.seq }
        var posted = 0
        for signed in mine where posted < Self.republishBatch {
            let missing = hosts.filter { convo.state.receipt(node: $0.0, item: signed.hash) == nil }
            guard !missing.isEmpty else { continue }
            posted += 1
            let digest = Hashing.sha256(signed.wire)
            for (_, url) in missing {
                postBytes(url + NodeAPI.item(convo.groupID, kind: .message), signed.wire) { [weak self] ok, bytes in
                    guard let self, ok, let receipt = try? Receipt.fromWire(bytes), receipt.isValid,
                          receipt.body.itemHash == signed.hash, receipt.body.contentDigest == digest else { return }
                    let first = !convo.state.receipts.values.contains { $0[signed.hash] != nil }
                    convo.state.recordReceipt(receipt)
                    self.saveReceipts(convo)
                    self.noteReachable(url)
                    if first { self.refreshMessages(convo) }
                }
            }
        }
    }

    public func scanInvite() {
        guard let host else { return }
        ConvoServices.request({ [weak self] ok, payload in
            guard let self, ok, !payload.isEmpty, let marker = payload.firstIndex(of: "#") else { return }
            self.consumeOpeningHash(String(payload[marker...]))
        }, { host.scanQR(requestID: $0) })
    }

    public func cancelPairing() {
        inviteGeneration += 1
        handshakeSalt = nil
        forgetShownInvite()
        creator = nil
        joiner = nil
        inviteLink = ""
        inviteQRImage = ""
        status = ""
        pairingContactID = nil
        pendingNaming = nil
        host?.setHash(value: "")
        host?.drawQR(elementID: "invite-qr", text: "")
        phase = .idle
        pairingVisible = false
    }

    private func renderQR(_ text: String, generation: Int, assign: @escaping (Client, String) -> Void) {
        guard let host else { return }
        ConvoServices.request({ [weak self] ok, payload in
            guard let self, ok, self.inviteGeneration == generation, self.phase != .idle else { return }
            assign(self, payload)
        }, { host.qrImage(requestID: $0, text: text) })
    }

    public func shareInvite() {
        guard !inviteLink.isEmpty else { return }
        host?.share(text: inviteLink)
    }

    public func saveInviteCode() {
        guard !inviteLink.isEmpty else { return }
        host?.saveQR(elementID: "invite-qr")
    }

    private static func bytes(hex: String) -> [UInt8]? {
        guard hex.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b); i = j
        }
        return out
    }

    private static func base64URL(_ data: Data) -> String {
        String(data.base64EncodedString().compactMap { c -> Character? in
            switch c {
            case "+": return "-"
            case "/": return "_"
            case "=": return nil
            default: return c
            }
        })
    }

    private static func fromBase64URL(_ text: String) -> Data? {
        var padded = String(text.map { c -> Character in
            switch c {
            case "-": return "+"
            case "_": return "/"
            default: return c
            }
        })
        while padded.count % 4 != 0 { padded += "=" }
        return Data(base64Encoded: padded)
    }

    /// Forget a contact: close the link and drop the group from this
    /// device. Their copy stays until they do the same.
    public func unpair(_ contactID: String) {
        if let convo = conversation(with: contactID) {
            convo.reconnecting = false
            host?.closeConnection(peer: convo.transportID)
            host?.save(key: "group:" + convo.groupID.hex, value: "")
            host?.save(key: "messages:" + convo.groupID.hex, value: "")
        }
        conversationStore.removeAll { $0.contactID == contactID }
        contacts.removeAll { $0.id == contactID }
        saveContacts()
        touch()
    }

    // MARK: - Messages through the hosts (§10, §14–16)

    private var pulling = false

    /// Every few seconds: fetch what each group's hosts hold, verify,
    /// ack. Live delivery also rides the data channel when it is up.
    private func pullLoop() {
        guard let host, !pulling else { return }
        pulling = true
        func tick() {
            for convo in conversations { pull(convo); republishQueued(convo); rotateEpochIfDue(convo); watchSync(convo) }
            ConvoServices.request({ [weak self] _, _ in
                guard let self else { return }
                if self.conversations.isEmpty { self.pulling = false } else { tick() }
            }, { host.delay(requestID: $0, ms: 4_000) })
        }
        tick()
    }

    private func hostURLs(_ convo: Conversation) -> [String] {
        var urls = convo.state.hosts.compactMap { url(forNode: $0) }
        if urls.isEmpty { urls = rendezvousURLs(for: convo.groupID) }   // §13.1 fallback
        return urls
    }

    private func pull(_ convo: Conversation) {
        // A request is signed against the nodes' clock; before the first
        // reading, ask for it rather than trust this device's clock (a
        // request too far off is refused as expired).
        guard timeReading != nil else {
            if let url = hostURLs(convo).first { healthCheck(url) { [weak self] _ in if self?.timeReading != nil { self?.pull(convo) } } }
            return
        }
        let time = nodeTime()
        for url in hostURLs(convo) {
            let have = convo.state.head == convo.groupID ? Hash32.zero : convo.state.head
            let request = FetchRequest.sign(.init(requesterPk: convo.state.groupKey.publicKey, groupID: convo.groupID,
                                                  want: .range(sinceHead: have, head: Hash32.zero),
                                                  nonce: (0..<16).map { _ in UInt8.random(in: 0...255) }, time: time), with: convo.state.groupKey)
            postBytes(url + NodeAPI.fetch(convo.groupID), request.wire) { [weak self] ok, bytes in
                guard let self, ok, let reply = try? FetchReply.fromWire(bytes), reply.response.isValid,
                      reply.response.body.requestHash == request.requestHash else { return }
                // §15: a reply whose time is below the request's is no reply.
                guard reply.response.body.time >= request.body.time else {
                    // Nothing to replay against before the first reading: take
                    // this node's clock and ask again properly.
                    if self.timeReading == nil { self.noteTime(reply.response.body.time); self.pull(convo); return }
                    print("[convo] fetch at \(url) answered below the request's time (request \(time), node \(reply.response.body.time)); dropped")
                    return
                }
                // The reply names the node's clock: the reading every later
                // request is signed against. A request the node called
                // expired was signed against a stale or absent reading;
                // with the clock reset, ask again now rather than in 4s.
                let wasSynced = self.timeReading != nil
                self.noteTime(reply.response.body.time)
                if reply.response.body.status != FetchStatus.found.rawValue {
                    print("[convo] fetch at \(url) answered \(reply.response.body.status) (request time \(time), node time \(reply.response.body.time), head \(have.hex.prefix(8)))")
                }
                if reply.response.body.status == FetchStatus.expired.rawValue {
                    if !wasSynced || abs(Int64(time) - Int64(reply.response.body.time)) > Int64(Parameters.Node.requestMaxAheadMs) { self.pull(convo) }
                    return
                }
                var fresh = false
                for (i, item) in reply.items.enumerated() where i < reply.response.body.served.count {
                    let (hash, digest) = reply.response.body.served[i]
                    guard Hashing.sha256(item) == digest else { continue }
                    if let m = try? SignedMessage.fromWire(item), m.hash == hash {
                        do { if try convo.state.receive(m) { fresh = true } } catch {
                            print("[convo] could not take message \(hash.hex.prefix(8)) by \(m.message.authorIdx)/\(m.message.seq) from \(url): \(error)")
                        }
                    } else if let a = try? SignedAttestation.fromWire(item) {
                        convo.state.receive(a)
                    } else { continue }
                    let key = url + hash.hex
                    if !convo.acked.contains(key) {
                        convo.acked.insert(key)
                        let ack = Ack.sign(.init(recipientPk: convo.state.groupKey.publicKey, nodePk: reply.response.body.nodePk, groupID: convo.groupID, itemHash: hash, time: time), with: convo.state.groupKey)
                        self.postBytes(url + NodeAPI.ack(convo.groupID), ack.wire) { _, _ in }
                    }
                }
                if fresh {
                    self.refreshMessages(convo)
                    self.saveMessages(convo)
                }
            }
        }
    }

    /// A reaction (kind 3) on one of the thread's messages; the same emoji
    /// again takes ours back.
    public func react(to messageID: String, emoji: String, in convo: Conversation) {
        guard let target = Hash32(hex: messageID) else { return }
        let mine = convo.messages.first { $0.id == messageID }?.reactions?.contains { $0.emoji == emoji && $0.mine } ?? false
        do {
            let signed = try convo.state.sendReaction(to: target, emoji: emoji, remove: mine, ts: nowMS())
            refreshMessages(convo)
            saveMessages(convo)
            saveGroup(convo)
            publish(signed, in: convo)
        } catch {
            status = "could not react: \(error)"
        }
    }

    /// A picture (kind 4): the host picks and downscales it, the bytes are
    /// sealed with a fresh key and put at every host as a blob, and the
    /// message carries the blob's name, the key and the shape.
    public func sendImage(in convo: Conversation) {
        guard let host else { return }
        ConvoServices.request({ [weak self] ok, payload in
            guard let self, ok else { return }
            let parts = payload.split(separator: "|", maxSplits: 3).map(String.init)
            guard parts.count == 4, let width = UInt32(parts[1]), let height = UInt32(parts[2]), let bytes = Data(base64Encoded: parts[3]) else { return }
            let mime = parts[0]
            do {
                let (key, sealed) = try BlobSeal.seal(Array(bytes))
                let name = BlobSeal.name(of: sealed)
                for url in self.hostURLs(convo) { self.postBytes(url + NodeAPI.blob(convo.groupID, name), sealed) { _, _ in } }
                let attachment = Attachment(blob: name, key: key, mime: mime, width: width, height: height, size: UInt64(sealed.count))
                let signed = try convo.state.sendAttachment(attachment, ts: self.nowMS())
                ConvoServices.request({ [weak self] ok, url in
                    guard let self, ok else { return }
                    convo.imageURLs[signed.hash.hex] = url
                    self.refreshMessages(convo)
                }, { host.imageURL(requestID: $0, key: name.hex, bytes64: parts[3], mime: mime) })
                self.refreshMessages(convo)
                self.saveMessages(convo)
                self.saveGroup(convo)
                self.publish(signed, in: convo)
            } catch {
                self.status = "could not send the picture: \(error)"
            }
        }, { host.pickImage(requestID: $0) })
    }

    /// Fetches an attachment's blob from the first host that has it, opens
    /// it, and hands the bytes to the host for showing.
    private func resolveAttachment(_ attachment: Attachment, of hash: Hash32, in convo: Conversation) {
        guard let host, !convo.fetchingBlobs.contains(hash.hex) else { return }
        convo.fetchingBlobs.insert(hash.hex)
        let urls = hostURLs(convo)
        func attempt(_ i: Int) {
            guard i < urls.count else { convo.fetchingBlobs.remove(hash.hex); return }
            getBytes(urls[i] + NodeAPI.blob(convo.groupID, attachment.blob)) { [weak self] ok, sealed in
                guard let self else { return }
                guard ok, BlobSeal.name(of: sealed) == attachment.blob, let plain = try? BlobSeal.open(sealed, key: attachment.key) else { attempt(i + 1); return }
                ConvoServices.request({ [weak self] ok, url in
                    guard let self else { return }
                    convo.fetchingBlobs.remove(hash.hex)
                    guard ok else { return }
                    convo.imageURLs[hash.hex] = url
                    self.refreshMessages(convo)
                }, { host.imageURL(requestID: $0, key: attachment.blob.hex, bytes64: Data(plain).base64EncodedString(), mime: attachment.mime) })
            }
        }
        attempt(0)
    }

    public func send(_ text: String, in convo: Conversation) {
        let body = Self.trim(text)
        guard !body.isEmpty, let host else { return }
        do {
            let signed = try convo.state.send(body, ts: nowMS())
            refreshMessages(convo)
            saveMessages(convo)
            saveGroup(convo)   // the sender generation moved
            // §10: to online peers over the channel, and to every host.
            publish(signed, in: convo)
            rotateEpochIfDue(convo)
        } catch {
            status = "could not send: \(error)"
        }
    }

    /// §9.2: while another member's attestation names a head this member
    /// does not hold, ask the hosts for it by hash on every tick; after
    /// `RECOVERY_PATIENCE` without it, start a recovery fork (member 0 at
    /// once, member 1 after the stagger, so both do not race).
    private func watchSync(_ convo: Conversation) {
        let missing = convo.state.unheldAttestedHeads
        guard !missing.isEmpty else {
            if convo.syncingSince != nil { convo.syncingSince = nil; host?.save(key: "syncing:" + convo.groupID.hex, value: "") }
            return
        }
        let t = now()
        if convo.syncingSince == nil {
            convo.syncingSince = t
            host?.save(key: "syncing:" + convo.groupID.hex, value: String(t))
        }
        for hash in missing.prefix(8) { fetchItem(hash, in: convo) }
        let patience = Self.recoveryPatience + (convo.state.memberIdx == 0 ? 0 : Parameters.Client.forkStaggerSeconds)
        if convo.forkSalt == nil, t - (convo.syncingSince ?? t) >= patience {
            convo.chainStatus = "no answer to the sync in \(Int(Self.recoveryPatience / 86_400)) days; starting over from the last sound point"
            beginRecoveryFork(convo)
        }
    }

    /// `CONVO_DEBUG_RECOVERY_PATIENCE`: seconds, for tests; the spec's 14 days otherwise.
    private static let recoveryPatience: Double = ProcessInfo.processInfo.environment["CONVO_DEBUG_RECOVERY_PATIENCE"].flatMap(Double.init)
        ?? Parameters.Client.recoveryPatienceSeconds

    /// One item by hash from the hosts (§12 against the mailbox).
    private func fetchItem(_ hash: Hash32, in convo: Conversation) {
        guard timeReading != nil else { return }
        let time = nodeTime()
        for url in hostURLs(convo).prefix(2) {
            let request = FetchRequest.sign(.init(requesterPk: convo.state.groupKey.publicKey, groupID: convo.groupID, want: .item(hash),
                                                  nonce: (0..<16).map { _ in UInt8.random(in: 0...255) }, time: time), with: convo.state.groupKey)
            postBytes(url + NodeAPI.fetch(convo.groupID), request.wire) { [weak self] ok, bytes in
                guard let self, ok, let reply = try? FetchReply.fromWire(bytes), reply.response.isValid,
                      reply.response.body.requestHash == request.requestHash, reply.response.body.time >= request.body.time else { return }
                self.noteTime(reply.response.body.time)
                var fresh = false
                for (i, item) in reply.items.enumerated() where i < reply.response.body.served.count {
                    guard Hashing.sha256(item) == reply.response.body.served[i].1, let m = try? SignedMessage.fromWire(item) else { continue }
                    if (try? convo.state.receive(m)) == true { fresh = true }
                }
                if fresh { self.refreshMessages(convo); self.saveMessages(convo) }
            }
        }
    }

    /// §2: a self-Update commit after `MLS_UPDATE_INTERVAL` of own
    /// activity, by count or on the clock, so a compromised key stops
    /// reading once the others have the next epoch.
    private func rotateEpochIfDue(_ convo: Conversation) {
        guard convo.state.epochUpdateDue(at: nowMS()) else { return }
        do {
            let update = try convo.state.rotateEpoch(ts: nowMS())
            saveMessages(convo)
            saveGroup(convo)
            publish(update, in: convo)
        } catch {
            status = "could not rotate the keys: \(error)"
        }
    }

    // MARK: - The peer channel (Part III §22–§23)
    //
    // The lower identity offers; the higher one answers from its signaling
    // box. Both poll their box at every healthy node while the link is
    // down. SDP comes gathered, so no candidate frames are needed.

    private static let reconnectMS: Int32 = 15_000

    private func beginReconnect(_ convo: Conversation) {
        guard !convo.connected, !convo.reconnecting else { return }
        convo.reconnecting = true
        touch()
        pollLoop()
        if selfID < convo.contactID { offerLoop(convo) }
        else { convo.linkStatus = healthyNodeURLs.isEmpty ? Self.noServerStatus : "Waiting for them to find us…" }
    }

    public func reconnectNow(_ convo: Conversation) {
        guard !convo.connected else { return }
        convo.reconnecting = true
        touch()
        pollLoop()
        offerLoop(convo)
    }

    private func offerLoop(_ convo: Conversation) {
        guard let host, convo.reconnecting, !convo.connected, !convo.offering else { return }
        convo.offering = true
        withICE { [weak self] in
            guard let self else { return }
            ConvoServices.request({ [weak self] ok, sdp in
                guard let self, self.conversation(with: convo.contactID) === convo else { return }
                convo.offering = false
                if ok, let peer = Hash32(hex: convo.contactID) {
                    self.drop(SignalingFrame.offer(sdp: sdp).wire, box: NodeAPI.handshakeBox(salt: convo.groupID, recipient: peer), urls: self.healthyNodeURLs)
                    convo.linkStatus = self.healthyNodeURLs.isEmpty ? Self.noServerStatus : "Looking for them through \(self.healthyNodeURLs.count) node(s)…"
                }
                self.touch()
                ConvoServices.request({ [weak self] _, _ in self?.offerLoop(convo) }, { host.delay(requestID: $0, ms: Self.reconnectMS) })
            }, { host.createOffer(requestID: $0, peer: convo.transportID) })
        }
    }

    private func signalingFrame(_ bytes: [UInt8], in convo: Conversation) {
        guard let host, let frame = try? SignalingFrame.fromWire(bytes), let peer = Hash32(hex: convo.contactID) else { return }
        switch frame {
        case .offer(let sdp):
            guard !convo.connected else { return }
            withICE { [weak self] in
                guard let self else { return }
                ConvoServices.request({ [weak self] ok, answer in
                    guard let self, ok else { return }
                    self.drop(SignalingFrame.answer(sdp: answer).wire, box: NodeAPI.handshakeBox(salt: convo.groupID, recipient: peer), urls: self.healthyNodeURLs)
                }, { host.acceptOffer(requestID: $0, peer: convo.transportID, blob: sdp) })
            }
        case .answer(let sdp):
            guard !convo.connected else { return }
            host.acceptAnswer(requestID: 0, peer: convo.transportID, blob: sdp)
        case .candidate:
            break   // descriptions travel gathered
        }
    }

    // MARK: - Host events

    /// How long a connection may sit "disconnected" before it is counted as
    /// down and rebuilt.
    private static let disconnectGraceMS: Int32 = 10_000

    /// The link is gone: a call on it ends, and the side that offers starts
    /// offering again.
    private func linkDown(_ convo: Conversation, transportID: String) {
        convo.channelOpen = false
        if convo.callState != .none {
            convo.callState = .none
            convo.callVideo = false
            host?.callEnd(peer: transportID)
        }
        convo.connected = false
        convo.reconnecting = false
        touch()
        beginReconnect(convo)
    }

    private func handle(kind: String, payload: String) {
        switch kind {
        case "state":
            let parts = payload.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { return }
            let transportID = String(parts[0]), state = String(parts[1])
            guard let convo = conversation(forTransport: transportID) else { return }
            convo.linkState = state
            switch state {
            case "connected":
                // Back from a dip: the channel it carried is still open.
                guard convo.channelOpen, !convo.connected else { return }
                convo.connected = true
                convo.reconnecting = false
                convo.linkStatus = ""
                touch()
            case "disconnected":
                // Often a blip (a call's renegotiation, a network hiccup)
                // that ICE recovers from by itself: down only if it is still
                // down after the grace. Tearing it down at once left one
                // side "offline" beside a working channel, and the side
                // that offers — seeing it up — never offered again.
                guard let host else { return }
                ConvoServices.request({ [weak self] _, _ in
                    guard let self, convo.linkState == "disconnected" else { return }
                    self.linkDown(convo, transportID: transportID)
                }, { host.delay(requestID: $0, ms: Self.disconnectGraceMS) })
            case "failed", "closed":
                linkDown(convo, transportID: transportID)
            default:
                break
            }
        case "open":
            guard let convo = conversation(forTransport: payload) else { return }
            convo.channelOpen = true
            convo.linkState = "connected"
            convo.connected = true
            convo.reconnecting = false
            convo.linkStatus = ""
            touch()
            status = "connected"
        case "frame":
            let parts = payload.split(separator: " ", maxSplits: 1)
            guard parts.count == 2, let convo = conversation(forTransport: String(parts[0])),
                  let bytes = Data(base64Encoded: String(parts[1])) else { return }
            receive(Array(bytes), in: convo)
        case "error":
            status = payload
        default:
            break
        }
    }

    /// A frame on the channel (§23): a message, or a call frame (§25).
    private func receive(_ bytes: [UInt8], in convo: Conversation) {
        guard let tag = bytes.first else { return }
        if tag == SyncFrame.message {
            guard let m = try? SignedMessage.fromWire(Array(bytes.dropFirst())), (try? convo.state.receive(m)) == true else { return }
            refreshMessages(convo)
            saveMessages(convo)
            return
        }
        if tag == SyncFrame.attestation {
            if let a = try? SignedAttestation.fromWire(Array(bytes.dropFirst())), convo.state.receive(a) { refreshMessages(convo) }
            return
        }
        guard let frame = try? CallFrame.fromWire(bytes) else { return }
        switch frame {
        case .offer(let sdp, let video): handleCallOffer(sdp, video: video, in: convo)
        case .answer(let sdp): handleCallAnswer(sdp, in: convo)
        case .end: handleCallEnd(in: convo)
        }
    }

    // MARK: - Recovery forks (§9.2, §9.8, §9.3, §9.4)
    //
    // An unsound lock leaves the group unusable. Member 0 starts a fork at
    // once, member 1 after the stagger if no invite has come: a new
    // handshake with the same two identities, homed on the same nodes,
    // with a ParentRef at the last sound checkpoint, and the salt told to
    // the peer as a control message in the old group. Both sides carry
    // (§9.3), so the chain records the successor; own messages past the
    // fork point are republished (§9.4); the old thread stays visible.

    /// Starts a recovery fork (§9.2) as its creator, at the latest head
    /// this member holds a committed attestation for. Public for the
    /// debug hooks; the client loop calls it after `RECOVERY_PATIENCE`
    /// without a sync (not yet wired).
    public func beginRecoveryFork(_ convo: Conversation) {
        guard let identity, let mine = keyPackage, convo.forkSalt == nil,
              let peer = convo.state.roster.first(where: { $0.body.identityPk != identity.publicKey }) else { return }
        let cited = convo.state.latestCommittedAttestedHead.flatMap { convo.state.parentRef(head: $0) }
        let proposal = HandshakeFrame.Proposal.defaults(members: 2, homeNodes: convo.state.genesis.homeNodes, parent: cited?.ref,
                                                        parentAttestation: cited?.attestation, reason: cited == nil ? .root : .recovery)
        do {
            let c = try HandshakeCreator(identity: identity, roster: [mine, peer], proposal: proposal)
            c.parentMembers = convo.state.genesis.members
            c.parentIdentities = convo.state.identities
            convo.forkCreator = c
            convo.forkSalt = c.salt
            drop(c.invite(), box: NodeAPI.handshakeBox(salt: c.salt, recipient: peer.body.identityPk), urls: healthyNodeURLs)
            if let control = try? convo.state.control("fork:" + c.salt.hex, ts: nowMS()) { publish(control, in: convo); saveMessages(convo); saveGroup(convo) }
            convo.chainStatus = "starting a new conversation from \(cited.map { String($0.ref.head.hex.prefix(8)) } ?? "the beginning")"
            touch()
            pollLoop()
        } catch {
            status = "could not start the recovery: \(error)"
        }
    }

    private func joinRecoveryFork(_ convo: Conversation, salt: Hash32) {
        guard let identity, convo.forkSalt == nil else { return }
        let j = HandshakeJoiner(identity: identity)
        j.minTotalHosts = 1
        j.parentMembers = convo.state.genesis.members
        convo.forkJoiner = j
        convo.forkSalt = salt
        convo.chainStatus = "joining the new conversation"
        touch()
        pollLoop()
    }

    /// A frame in this identity's box for the fork's salt.
    private func forkFrame(_ frame: [UInt8], in convo: Conversation) {
        guard let salt = convo.forkSalt else { return }
        if let c = convo.forkCreator {
            let before = c.carrySigs.count
            guard let reply = try? c.receive(frame) else {
                // A carry from the peer: the node can record it now (§11.3).
                // The creator's half of the handshake lives on the child
                // conversation once the group exists.
                if c.carrySigs.count > before, let g = c.genesis, let child = conversation(with: convo.contactID), child.groupID == g.groupID {
                    child.carrySigs = c.carrySigs
                    publishGenesis(child)
                    if c.carrySigs.count >= c.roster.count { child.forkCreator = nil; child.forkSalt = nil }
                }
                return
            }
            // The announce completed the roster: the genesis goes to the
            // peer, this side's carry joins it, and the group is live.
            drop(reply, box: NodeAPI.handshakeBox(salt: salt, recipient: c.roster[1].body.identityPk), urls: healthyNodeURLs)
            guard let g = c.genesis else { return }
            let (idx, sig) = convo.state.carrySignature(for: g.groupID)
            _ = try? c.receive({ var w = BorshWriter(); w.u8(HandshakeFrame.carry); w.u8(idx); w.fixed(sig); return w.bytes }())
            guard let state = try? c.session() else { return }
            finishFork(convo, child: state, carrySigs: c.carrySigs)
            return
        }
        if let j = convo.forkJoiner {
            if let reply = try? j.receive(frame) {
                if let creator = j.roster.first?.body.identityPk { drop(reply, box: NodeAPI.handshakeBox(salt: salt, recipient: creator), urls: healthyNodeURLs) }
                return
            }
            guard j.genesis != nil, let creator = j.roster.first?.body.identityPk else { return }
            if let carry = try? j.carry(parentIdx: convo.state.memberIdx, parentKey: convo.state.groupKey) {
                drop(carry, box: NodeAPI.handshakeBox(salt: salt, recipient: creator), urls: healthyNodeURLs)
            }
            guard let state = try? j.session() else { return }
            finishFork(convo, child: state, carrySigs: [])
        }
    }

    /// The new group replaces the old one for the contact: same thread,
    /// the old messages kept above, own messages past the fork point
    /// republished, the genesis handed to a home node (the creator).
    private func finishFork(_ old: Conversation, child state: GroupState, carrySigs: [(UInt8, [UInt8])]) {
        state.setParent(members: old.state.genesis.members)
        let convo = Conversation(contactID: old.contactID, state: state)
        convo.archived = old.messages.map { var m = $0; m.state = "archived"; return m }
        convo.carrySigs = carrySigs
        conversationStore.removeAll { $0 === old }
        conversationStore.append(convo)
        if let at = contacts.firstIndex(where: { $0.id == old.contactID }) { contacts[at].groupID = state.groupID.hex }
        saveContacts()
        saveGroup(convo)
        if old.connected { host?.closeConnection(peer: old.transportID) }
        // The creator keeps collecting the peer's carry; the joiner is done.
        if old.forkCreator != nil { convo.forkCreator = old.forkCreator; convo.forkSalt = old.forkSalt }
        old.forkSalt = nil; old.forkCreator = nil; old.forkJoiner = nil
        if let ref = state.genesis.parent {
            for rp in old.state.republishes(after: ref.head) {
                if let signed = try? state.republish(rp, ts: nowMS()) { publish(signed, in: convo) }
            }
            for text in old.state.uncommittedOwnTexts() { if let signed = try? state.send(text, ts: nowMS()) { publish(signed, in: convo) } }
        }
        convo.chainStatus = "new conversation"
        status = "\(displayName(for: convo.contactID)): a new conversation was started"
        refreshMessages(convo)
        saveMessages(convo)
        if !carrySigs.isEmpty { publishGenesis(convo) }
        beginReconnect(convo)
        pullLoop()
        commitLoop()
    }

    // MARK: - Calls (Part III §25)

    public enum CallState: Equatable {
        case none
        case outgoingRinging
        case incomingRinging(sdp: String)
        case declined(sdp: String)
        case active
    }

    public var activeVideoCall: Conversation? {
        conversations.first { $0.callVideo && $0.callState == .active }
    }

    public func transport(for contactID: String) -> String? {
        conversation(with: contactID)?.transportID
    }

    public var activeCallConversation: Conversation? {
        conversations.first {
            switch $0.callState {
            case .none, .declined: return false
            default: return true
            }
        }
    }

    /// How long a call rings before it gives up.
    private static let ringTimeoutMS: Int32 = 60_000

    private func sendCall(_ frame: CallFrame, in convo: Conversation) {
        host?.sendFrame(peer: convo.transportID, text: Data(frame.wire).base64EncodedString())
    }

    public func startCall(in convo: Conversation, video: Bool = false) {
        guard let host, convo.connected, convo.callState == .none, activeCallConversation == nil else { return }
        convo.callState = .outgoingRinging
        convo.callVideo = video
        convo.callNote = ""
        convo.callSerial += 1
        let serial = convo.callSerial
        touch()
        // Unanswered, a call ends by itself: ringing forever is worse than
        // a missed call, and an answer that was lost never arrives.
        ConvoServices.request({ [weak self] _, _ in
            guard let self, convo.callSerial == serial, convo.callState == .outgoingRinging else { return }
            convo.callNote = "No answer"
            self.hangUp(in: convo)
        }, { host.delay(requestID: $0, ms: Self.ringTimeoutMS) })
        ConvoServices.request({ [weak self] ok, sdp in
            guard let self else { return }
            guard ok, !sdp.isEmpty else {
                convo.callState = .none
                convo.callVideo = false
                self.status = video ? "couldn't start the call (camera or microphone?)" : "couldn't start the call (microphone?)"
                convo.callNote = "Couldn't start the call" + (sdp.isEmpty ? "" : ": " + sdp)
                self.touch()
                return
            }
            self.sendCall(.offer(sdp: sdp, video: video), in: convo)
        }, { host.callStart(requestID: $0, peer: convo.transportID, video: video) })
    }

    private func handleCallOffer(_ sdp: String, video: Bool, in convo: Conversation) {
        guard convo.connected else { return }
        if convo.callState == .active {
            applyRemoteCall(sdp: sdp, isOffer: true, in: convo)
            return
        }
        convo.callState = .incomingRinging(sdp: sdp)
        convo.callVideo = video
        convo.callNote = ""
        touch()
    }

    public func acceptCall(in convo: Conversation) {
        guard activeCallConversation == nil || activeCallConversation === convo else { return }
        switch convo.callState {
        case .incomingRinging(let sdp), .declined(let sdp):
            applyRemoteCall(sdp: sdp, isOffer: true, in: convo)
        default:
            return
        }
    }

    public func declineCall(in convo: Conversation) {
        guard case .incomingRinging(let sdp) = convo.callState else { return }
        convo.callState = .declined(sdp: sdp)
        touch()
    }

    public func hangUp(in convo: Conversation) {
        guard let host, convo.callState != .none else { return }
        status = "hung up"
        convo.callState = .none
        convo.callVideo = false
        touch()
        host.callEnd(peer: convo.transportID)
        sendCall(.end, in: convo)
    }

    private func applyRemoteCall(sdp: String, isOffer: Bool, in convo: Conversation) {
        guard let host else { return }
        ConvoServices.request({ [weak self] ok, answer in
            guard let self else { return }
            guard ok else {
                convo.callState = .none
                convo.callVideo = false
                self.status = "call media failed"
                convo.callNote = "The call failed" + (answer.isEmpty ? "" : ": " + answer)
                self.touch()
                // The other side is still ringing (or waiting on this
                // answer): tell it, or it waits for ever.
                self.host?.callEnd(peer: convo.transportID)
                self.sendCall(.end, in: convo)
                return
            }
            if isOffer, !answer.isEmpty { self.sendCall(.answer(sdp: answer), in: convo) }
            convo.callState = .active
            self.touch()
        }, { host.callApplyRemote(requestID: $0, peer: convo.transportID, sdp: sdp, isOffer: isOffer, video: convo.callVideo) })
    }

    private func handleCallAnswer(_ sdp: String, in convo: Conversation) {
        guard convo.callState == .outgoingRinging || convo.callState == .active else { return }
        applyRemoteCall(sdp: sdp, isOffer: false, in: convo)
    }

    private func handleCallEnd(in convo: Conversation) {
        guard convo.callState != .none else { return }
        status = "they ended the call"
        if convo.callState == .outgoingRinging { convo.callNote = "They couldn't join the call" }
        convo.callState = .none
        convo.callVideo = false
        touch()
        host?.callEnd(peer: convo.transportID)
    }

    // MARK: - Display helpers

    public static func timeLabel(for timestamp: Double, now: Double? = nil) -> String {
        #if canImport(FoundationEssentials)
        typealias D = FoundationEssentials.Date
        #else
        typealias D = Foundation.Date
        #endif
        let calendar = Calendar.current
        let when = D(timeIntervalSince1970: timestamp)
        let today = D(timeIntervalSince1970: now ?? D().timeIntervalSince1970)
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute, .weekday], from: when)
        guard let hour = parts.hour, let minute = parts.minute, let year = parts.year, let month = parts.month,
              let day = parts.day, let weekday = parts.weekday else { return "" }
        if calendar.isDate(when, inSameDayAs: today) {
            let h12 = hour % 12 == 0 ? 12 : hour % 12
            return "\(h12):\(minute < 10 ? "0" : "")\(minute) \(hour < 12 ? "AM" : "PM")"
        }
        if today.timeIntervalSince1970 - timestamp < 6 * 86400 {
            return ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][(weekday - 1) % 7]
        }
        return "\(month)/\(day)/\(year % 100 < 10 ? "0" : "")\(year % 100)"
    }

    /// "ab12 cd34 ef56 7890": the first 16 hex characters of an identity,
    /// spaced for humans to compare aloud.
    public static func displayFingerprint(_ id: String) -> String {
        let short = String(id.prefix(16))
        return stride(from: 0, to: short.count, by: 4).map { at in
            let start = short.index(short.startIndex, offsetBy: at)
            let end = short.index(start, offsetBy: 4, limitedBy: short.endIndex) ?? short.endIndex
            return String(short[start..<end])
        }.joined(separator: " ")
    }
}
