import ConvoCore
import ConvoFoundation

/// A bidirectional byte channel to one peer: WebRTC data channels in the
/// app, loopback pipes in tests. Messages are delimited by the transport.
public protocol DataChannel: Sendable {
    func send(_ bytes: [UInt8]) async throws
    var incoming: AsyncStream<[UInt8]> { get }
    func close() async
}

/// Two channels joined back to back, for tests and the CLI's local mode.
public final class LoopbackChannel: DataChannel, @unchecked Sendable {
    private let sink: AsyncStream<[UInt8]>.Continuation
    public let incoming: AsyncStream<[UInt8]>
    private var peer: LoopbackChannel?

    private init() {
        var continuation: AsyncStream<[UInt8]>.Continuation!
        incoming = AsyncStream { continuation = $0 }
        sink = continuation
    }

    public static func pair() -> (LoopbackChannel, LoopbackChannel) {
        let a = LoopbackChannel(), b = LoopbackChannel()
        a.peer = b; b.peer = a
        return (a, b)
    }

    public func send(_ bytes: [UInt8]) async throws { peer?.sink.yield(bytes) }
    public func close() async { sink.finish(); peer?.sink.finish() }
}
