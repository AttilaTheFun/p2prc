import ConvoCore
import ConvoNet
import ConvoFoundation
import ConvoNodeCore

// The node as a WebAssembly reactor for a Cloudflare Durable Object
// (Worker/README.md). The Durable Object owns all I/O: it gives the reactor
// a WASI file system kept in its SQLite storage, makes the outbound calls the
// reactor asks for, and answers `/ice` itself. The reactor is the node's
// portable core (ConvoNodeCore) behind a few C-ABI exports that take and
// return JSON. A Durable Object is one instance per ID, so the node key has
// exactly one writer without a lease.

/// What the Durable Object passes at start (its environment).
struct WorkerConfig: Decodable {
    var id: String?
    var publicURL: String?
    var site: String?
    var operatorPk: String?
    var seeds: [String]?
    var witnesses: [String]?
    var turn: Bool?
    var stun: [String]?
    var commitIntervalMs: UInt64?
}

/// A request as the Durable Object hands it over; bodies in base64.
struct WorkerRequest: Decodable {
    var method: String
    var path: String
    var headers: [String: String]
    var body: String
    var peer: String
}

/// A call for the Durable Object to make.
struct Outbound: Codable {
    var method: String
    var url: String
    var body: String?
}

struct WorkerResponse: Encodable {
    var status: Int
    var contentType: String
    var body: String
    var outbound: [Outbound]
}

/// What the alarm leaves to do: witness requests (answered through
/// `convo_node_answers`), batch pushes, and when to run again.
struct AlarmResult: Encodable {
    var witness: [Outbound]
    var outbound: [Outbound]
    var nextAlarmMs: UInt64
    /// Something to finish: open items, or a checkpoint short of its quorum.
    var pending: Bool
}

/// A witness's answer to one request from `AlarmResult.witness`.
struct WitnessReply: Decodable {
    var url: String
    var request: String
    var status: Int
    var body: String
}

/// The node and its outbox. WebAssembly here has one thread, so nothing
/// is shared between threads; `@unchecked Sendable` lets the server's
/// `send` closure reach the outbox.
final class WorkerNode: @unchecked Sendable {
    let server: ConvoNodeServer
    let keeper: LogKeeper
    let witnesses: [String]
    private(set) var outbox: [Outbound] = []

    init(_ config: WorkerConfig) {
        let state = "/state"
        let key = ConvoNodeServer.loadOrCreateKey(stateDirectory: state)
        // The node's own /ice answer is STUN (its rate limit first); worker.js
        // adds a client's own TURN credential to one it lets through.
        let stun = config.stun ?? []
        let ice = StaticICE(offersTURN: config.turn ?? false, stunURLs: stun,
                            servers: stun.isEmpty ? [] : [ICEServer(urls: stun, username: nil, credential: nil)], ttl: 86_400)
        // A Durable Object's SQLite row holds 2 MB and its instance 128 MB,
        // which holds every file twice at start (wasi.js's copy and the
        // node's), the 14 MB module and each request's copies: smaller
        // blobs, a budget for them, and one for everything held for others
        // (worker.js refuses a larger body first).
        server = ConvoNodeServer(configuration: .init(id: config.id ?? "worker", publicURL: config.publicURL, site: config.site,
                                                      seeds: config.seeds ?? [], stateDirectory: state,
                                                      operatorPk: config.operatorPk.flatMap { Hash32(hex: $0) },
                                                      maxBlobBytes: Self.maxBlobBytes, maxBlobStoreBytes: 16 * 1024 * 1024,
                                                      maxStoredBytes: 24 * 1024 * 1024),
                                 key: key, ice: ice)
        keeper = LogKeeper(nodeKey: key, mailbox: server.mailbox)
        if let ms = config.commitIntervalMs { keeper.commitIntervalMs = ms }
        let own = config.publicURL.flatMap(ServerDirectory.normalize)
        witnesses = (config.witnesses ?? []).compactMap(ServerDirectory.normalize).filter { $0 != own }
        server.send = { [weak self] method, url, body in
            self?.outbox.append(Outbound(method: method, url: url, body: body.map { $0.base64EncodedString() }))
        }
    }

    static let maxBlobBytes = 1_500_000

    func takeOutbox() -> [Outbound] { defer { outbox = [] }; return outbox }

    func handle(_ request: WorkerRequest) -> WorkerResponse {
        let response = server.respond(to: HTTPRequest(method: request.method, path: request.path,
                                                      body: Data(base64Encoded: request.body) ?? Data(),
                                                      headers: request.headers, peer: request.peer))
        return WorkerResponse(status: response.status, contentType: response.contentType,
                              body: response.body.base64EncodedString(), outbound: takeOutbox())
    }

    func alarm(now: UInt64) -> AlarmResult {
        server.expireState()
        var pushes: [Outbound] = []
        if keeper.commitDue(now: now), let batch = try? keeper.close(now: now) {
            server.log?("closed batch \(batch.seq): \(batch.count) item(s)")
            // The body to the nodes this one knows, so proofs are available
            // from them too (§13).
            for url in witnesses { pushes.append(Outbound(method: "POST", url: url + NodeAPI.batches(keeper.nodePk), body: Data(batch.wire).base64EncodedString())) }
        }
        var requests: [Outbound] = []
        if keeper.needsCosignatures {
            for url in witnesses {
                guard let request = keeper.request(for: url) else { continue }
                requests.append(Outbound(method: "POST", url: url + NodeAPI.witness, body: Data(request.wire).base64EncodedString()))
            }
        }
        let next = now + min(keeper.commitIntervalMs, 60_000)
        return AlarmResult(witness: requests, outbound: pushes + takeOutbox(), nextAlarmMs: next,
                           pending: keeper.needsCosignatures || server.mailbox.openCount > 0)
    }

    /// Applies witnesses' answers; returns the requests to resend (a witness
    /// that was behind), which come back here the same way.
    func answers(_ replies: [WitnessReply]) -> [Outbound] {
        var retries: [Outbound] = []
        for reply in replies {
            guard let wire = Data(base64Encoded: reply.request), let request = try? WitnessRequest.fromWire(Array(wire)),
                  let body = Data(base64Encoded: reply.body) else { continue }
            let answer: NodeClient.WitnessAnswer
            if reply.status == 409 {
                var r = BorshReader(Array(body))
                guard let size = try? r.u64(), let latest = try? r.option({ try WitnessedCheckpoint(borshFrom: &$0) }) else { continue }
                answer = .conflict(size: size, latest: latest)
            } else if (200..<300).contains(reply.status), let cosignature = try? Cosignature.decode(Array(body)), cosignature.verifies(request.checkpoint) {
                answer = .cosigned(cosignature)
            } else {
                continue
            }
            let base = reply.url.hasSuffix(NodeAPI.witness) ? String(reply.url.dropLast(NodeAPI.witness.count)) : reply.url
            if let retry = keeper.apply(answer, from: base, to: request) {
                retries.append(Outbound(method: "POST", url: reply.url, body: Data(retry.wire).base64EncodedString()))
            }
        }
        return retries
    }
}

// MARK: - The C ABI the Durable Object calls

nonisolated(unsafe) private var node: WorkerNode?
nonisolated(unsafe) private var result: [UInt8] = []
nonisolated(unsafe) private var logLines: [String] = []

private func reply<T: Encodable>(_ value: T) -> Int32 {
    result = Array((try? JSONEncoder().encode(value)) ?? Data("{}".utf8))
    return Int32(result.count)
}

private func input(_ pointer: UnsafeRawPointer, _ length: Int32) -> Data {
    Data(bytes: pointer, count: Int(length))
}

private struct Failure: Encodable { var error: String }

@_expose(wasm, "convo_alloc")
@_cdecl("convo_alloc")
public func convoAlloc(_ length: Int32) -> UnsafeMutableRawPointer {
    UnsafeMutableRawPointer.allocate(byteCount: Int(max(length, 1)), alignment: 16)
}

@_expose(wasm, "convo_free")
@_cdecl("convo_free")
public func convoFree(_ pointer: UnsafeMutableRawPointer) { pointer.deallocate() }

/// The last call's JSON answer: its bytes, `convo_result_len` long.
@_expose(wasm, "convo_result_ptr")
@_cdecl("convo_result_ptr")
public func convoResultPtr() -> UnsafeRawPointer { result.withUnsafeBytes { UnsafeRawPointer($0.baseAddress!) } }

@_expose(wasm, "convo_result_len")
@_cdecl("convo_result_len")
public func convoResultLen() -> Int32 { Int32(result.count) }

/// Starts the node from its configuration (JSON `WorkerConfig`); answers
/// `{nodePk}`.
@_expose(wasm, "convo_node_init")
@_cdecl("convo_node_init")
public func convoNodeInit(_ pointer: UnsafeRawPointer, _ length: Int32) -> Int32 {
    guard let config = try? JSONDecoder().decode(WorkerConfig.self, from: input(pointer, length)) else {
        return reply(Failure(error: "bad config"))
    }
    let started = WorkerNode(config)
    started.server.log = { logLines.append($0) }
    node = started
    return reply(["nodePk": started.server.nodePk.hex])
}

/// One HTTP request (JSON `WorkerRequest`) → `WorkerResponse`.
@_expose(wasm, "convo_node_handle")
@_cdecl("convo_node_handle")
public func convoNodeHandle(_ pointer: UnsafeRawPointer, _ length: Int32) -> Int32 {
    guard let node else { return reply(Failure(error: "not started")) }
    guard let request = try? JSONDecoder().decode(WorkerRequest.self, from: input(pointer, length)) else {
        return reply(WorkerResponse(status: 400, contentType: "text/plain", body: Data("bad request".utf8).base64EncodedString(), outbound: []))
    }
    return reply(node.handle(request))
}

/// The alarm at `now` (unix ms) → `AlarmResult`.
@_expose(wasm, "convo_node_alarm")
@_cdecl("convo_node_alarm")
public func convoNodeAlarm(_ now: Double) -> Int32 {
    guard let node else { return reply(Failure(error: "not started")) }
    return reply(node.alarm(now: UInt64(max(0, now))))
}

/// Witnesses' answers (JSON `[WitnessReply]`) → the requests to resend.
@_expose(wasm, "convo_node_answers")
@_cdecl("convo_node_answers")
public func convoNodeAnswers(_ pointer: UnsafeRawPointer, _ length: Int32) -> Int32 {
    guard let node else { return reply(Failure(error: "not started")) }
    guard let replies = try? JSONDecoder().decode([WitnessReply].self, from: input(pointer, length)) else { return reply([Outbound]()) }
    return reply(node.answers(replies))
}

/// The node's log lines since the last call, as a JSON list.
@_expose(wasm, "convo_node_logs")
@_cdecl("convo_node_logs")
public func convoNodeLogs() -> Int32 {
    defer { logLines = [] }
    return reply(logLines)
}
