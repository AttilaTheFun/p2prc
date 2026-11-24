import Communication
import ConvoCore
import ConvoNet
import Foundation

/// Part III: a `DataChannel` over a Communication peer connection, so
/// `SyncClient`/`SyncResponder` run between two members' apps exactly as
/// they run over the loopback in tests. Frames are binary messages on
/// one data channel labelled "convo".
public final class PeerChannel: DataChannel, @unchecked Sendable {
    public static let label = "convo"
    public let connection: any CommunicationPeerConnection
    public let incoming: AsyncStream<[UInt8]>
    private let sink: AsyncStream<[UInt8]>.Continuation
    private let pump: Task<Void, Never>
    private let opened = Opened()

    private final class Opened: @unchecked Sendable {
        private let lock = NSLock()
        private var continuations: [CheckedContinuation<Void, Never>] = []
        private var isOpen = false
        func open() {
            lock.lock(); isOpen = true; let waiting = continuations; continuations = []; lock.unlock()
            for c in waiting { c.resume() }
        }
        func wait() async {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                lock.lock()
                if isOpen { lock.unlock(); c.resume(); return }
                continuations.append(c)
                lock.unlock()
            }
        }
    }

    public init(connection: any CommunicationPeerConnection) {
        self.connection = connection
        var sink: AsyncStream<[UInt8]>.Continuation!
        incoming = AsyncStream { sink = $0 }
        self.sink = sink
        let opened = self.opened
        let events = connection.events
        pump = Task { [sink] in
            for await event in events {
                switch event {
                case .dataChannelOpened(let label) where label == PeerChannel.label:
                    opened.open()
                case .dataChannelStateChanged(let label, let state) where label == PeerChannel.label:
                    if state == .open { opened.open() }
                    if state == .closed { sink?.finish() }
                case .dataChannelMessage(let label, let message) where label == PeerChannel.label:
                    if case .binary(let data) = message { sink?.yield(Array(data)) }
                case .connectionStateChanged(let state):
                    if state == .closed || state == .failed { sink?.finish() }
                default: break
                }
            }
            sink?.finish()
        }
    }

    /// The offerer opens the channel before creating the offer.
    public func open() async throws {
        try await connection.openDataChannel(label: Self.label, configuration: CommunicationDataChannelConfiguration(ordered: true))
    }

    /// Resolves once the channel is open on this side.
    public func ready() async { await opened.wait() }

    public func send(_ bytes: [UInt8]) async throws {
        await opened.wait()
        try await connection.send(data: Data(bytes), on: Self.label)
    }

    public func close() async {
        sink.finish()
        pump.cancel()
        await connection.close()
    }
}
