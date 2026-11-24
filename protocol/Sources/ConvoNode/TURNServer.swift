import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#elseif canImport(Darwin)
import Darwin
#endif

/// A TURN relay (RFC 5766 / RFC 8656) that is also a STUN server (RFC 5389
/// Binding), over UDP and TCP client transports, on POSIX sockets — so the
/// same code relays from a Mac, a phone, and a Linux container.
///
/// One thread runs a poll loop that owns every socket and all state; nothing
/// is shared, so there are no locks in the data path. Per allocation: a
/// relay UDP socket (bound to a port from `relayPorts`, so a NAT can have
/// them mapped ahead of time), permissions by peer IP (5 min), channels by
/// peer address (10 min), and a lifetime the client refreshes (default 10
/// min, capped at 1 h). Auth is long-term credentials with MD5 keys, which
/// every WebRTC stack speaks, minted in the TURN-REST shape by
/// `TURNCredentials` — the relay needs only the shared secret.
///
/// Policy stays outside: whether to run at all, what address to advertise,
/// which ports the NAT was told about. This class binds and relays.
public final class TURNServer: @unchecked Sendable {
    public struct Configuration: Sendable {
        /// Where clients talk to us (UDP and TCP, same port).
        public var listenPort: UInt16
        /// The address to write into XOR-RELAYED-ADDRESS: what peers must
        /// dial to reach a relay socket. The public/mapped address when
        /// behind a NAT, the machine's address otherwise.
        public var relayHost: String
        /// The ports relay sockets bind to. Small on a phone (a NAT mapping
        /// each), wide on a server. One allocation per port.
        public var relayPorts: ClosedRange<UInt16>
        public var credentials: TURNCredentials
        public var defaultLifetime: UInt32 = 600
        public var maxLifetime: UInt32 = 3600
        public var software = "p2prc-turn"

        public init(listenPort: UInt16, relayHost: String, relayPorts: ClosedRange<UInt16>, credentials: TURNCredentials) {
            self.listenPort = listenPort
            self.relayHost = relayHost
            self.relayPorts = relayPorts
            self.credentials = credentials
        }
    }

    public struct Stats: Sendable {
        public var allocations = 0
        public var relayedBytes = 0
    }

    private let configuration: Configuration
    private var udpFD: Int32 = -1
    private var tcpFD: Int32 = -1
    private var thread: Thread?
    private var running = false
    private let statsLock = NSLock()
    private var stats = Stats()
    public var log: (@Sendable (String) -> Void)?

    public init(configuration: Configuration) {
        self.configuration = configuration
    }

    public var currentStats: Stats {
        statsLock.lock(); defer { statsLock.unlock() }
        return stats
    }

    /// Binds both listeners (throws on a port in use) and starts the loop.
    public func start() throws {
        let bindAddress = SocketAddress(host: "0.0.0.0", port: configuration.listenPort)!
        udpFD = try Sockets.udp(bind: bindAddress)
        tcpFD = try Sockets.tcpListener(bind: bindAddress)
        Sockets.setNonBlocking(udpFD)
        Sockets.setNonBlocking(tcpFD)
        running = true
        let thread = Thread { [self] in self.loop() }
        thread.name = "p2prc-turn"
        thread.start()
        self.thread = thread
    }

    public func stop() {
        running = false
    }

    // MARK: - State (owned by the loop thread)

    /// A client's 5-tuple, the key for everything.
    private struct ClientKey: Hashable {
        let address: SocketAddress
        let tcpFD: Int32   // -1 for UDP
    }

    private final class Allocation {
        let client: ClientKey
        let relayFD: Int32
        let relayAddress: SocketAddress
        var expires: Date
        var permissions: [[UInt8]: Date] = [:]          // peer IP bytes -> expiry
        var channelsByNumber: [UInt16: (peer: SocketAddress, expires: Date)] = [:]
        var channelsByPeer: [SocketAddress: UInt16] = [:]
        let username: String
        init(client: ClientKey, relayFD: Int32, relayAddress: SocketAddress, expires: Date, username: String) {
            self.client = client
            self.relayFD = relayFD
            self.relayAddress = relayAddress
            self.expires = expires
            self.username = username
        }
    }

    private final class TCPClient {
        let fd: Int32
        let address: SocketAddress
        var buffer: [UInt8] = []
        init(fd: Int32, address: SocketAddress) {
            self.fd = fd
            self.address = address
        }
    }

    private var allocations: [ClientKey: Allocation] = [:]
    private var allocationsByRelayFD: [Int32: Allocation] = [:]
    private var tcpClients: [Int32: TCPClient] = [:]
    private var nonces: Set<String> = []
    private var usedRelayPorts: Set<UInt16> = []

    private static let permissionLifetime: TimeInterval = 300
    private static let channelLifetime: TimeInterval = 600

    // MARK: - Loop

    private func loop() {
        var buffer = [UInt8](repeating: 0, count: 65536)
        var lastSweep = Date()
        while running {
            var fds: [pollfd] = [
                pollfd(fd: udpFD, events: Int16(POLLIN), revents: 0),
                pollfd(fd: tcpFD, events: Int16(POLLIN), revents: 0),
            ]
            for fd in tcpClients.keys { fds.append(pollfd(fd: fd, events: Int16(POLLIN), revents: 0)) }
            for fd in allocationsByRelayFD.keys { fds.append(pollfd(fd: fd, events: Int16(POLLIN), revents: 0)) }
            let ready = poll(&fds, nfds_t(fds.count), 1000)
            if ready > 0 {
                for entry in fds where entry.revents & Int16(POLLIN | POLLHUP | POLLERR) != 0 {
                    if entry.fd == udpFD {
                        while let (count, from) = Sockets.receive(udpFD, into: &buffer) {
                            handleClientBytes(Array(buffer[0..<count]), from: ClientKey(address: from, tcpFD: -1))
                        }
                    } else if entry.fd == tcpFD {
                        acceptTCP()
                    } else if let client = tcpClients[entry.fd] {
                        readTCP(client, into: &buffer)
                    } else if let allocation = allocationsByRelayFD[entry.fd] {
                        while let (count, from) = Sockets.receive(entry.fd, into: &buffer) {
                            relayToClient(allocation, Array(buffer[0..<count]), from: from)
                        }
                    }
                }
            }
            if Date().timeIntervalSince(lastSweep) > 5 {
                sweepExpired()
                lastSweep = Date()
            }
        }
        for allocation in allocations.values { close(allocation.relayFD) }
        for client in tcpClients.values { close(client.fd) }
        close(udpFD)
        close(tcpFD)
    }

    private func acceptTCP() {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let fd = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(tcpFD, $0, &length) }
        }
        guard fd >= 0, let address = withUnsafePointer(to: &storage, { SocketAddress(storage: $0) }) else { return }
        Sockets.setNonBlocking(fd)
        tcpClients[fd] = TCPClient(fd: fd, address: address)
    }

    private func readTCP(_ client: TCPClient, into buffer: inout [UInt8]) {
        let received = recv(client.fd, &buffer, buffer.count, 0)
        if received <= 0 {
            dropTCPClient(client)
            return
        }
        client.buffer += buffer[0..<received]
        // Frame by STUN length or ChannelData length (padded on streams).
        while !client.buffer.isEmpty {
            let key = ClientKey(address: client.address, tcpFD: client.fd)
            if STUNMessage.looksLikeSTUN(client.buffer) || client.buffer[0] & 0xC0 == 0 {
                guard let length = STUNMessage.framedLength(client.buffer), client.buffer.count >= length else { return }
                handleClientBytes(Array(client.buffer[0..<length]), from: key)
                client.buffer.removeFirst(length)
            } else if ChannelData.looksLikeChannelData(client.buffer) {
                guard let frame = ChannelData.decode(client.buffer, stream: true) else { return }
                handleChannelData(channel: frame.channel, data: frame.data, from: key)
                client.buffer.removeFirst(frame.length)
            } else {
                dropTCPClient(client)
                return
            }
        }
    }

    private func dropTCPClient(_ client: TCPClient) {
        let key = ClientKey(address: client.address, tcpFD: client.fd)
        if let allocation = allocations[key] { release(allocation) }
        tcpClients[client.fd] = nil
        close(client.fd)
    }

    private func sendToClient(_ key: ClientKey, _ bytes: [UInt8], channelData: Bool = false) {
        if key.tcpFD >= 0 {
            Sockets.write(key.tcpFD, bytes)
        } else {
            Sockets.send(udpFD, bytes, to: key.address)
        }
    }

    // MARK: - Client messages

    private func handleClientBytes(_ bytes: [UInt8], from client: ClientKey) {
        if ChannelData.looksLikeChannelData(bytes) {
            if let frame = ChannelData.decode(bytes) {
                handleChannelData(channel: frame.channel, data: frame.data, from: client)
            }
            return
        }
        guard let message = STUNMessage.parse(bytes) else { return }
        switch (message.messageClass, message.method) {
        case (.request, .binding):
            var response = STUNMessage(method: .binding, messageClass: .success, transactionID: message.transactionID)
            response.addXORAddress(STUNMessage.AttributeType.xorMappedAddress, client.address)
            response.add(STUNMessage.AttributeType.software, string: configuration.software)
            sendToClient(client, response.encode(fingerprint: true))
        case (.request, .allocate), (.request, .refresh), (.request, .createPermission), (.request, .channelBind):
            guard let key = authenticate(message, raw: bytes, from: client) else { return }
            switch message.method {
            case .allocate: allocate(message, from: client, key: key)
            case .refresh: refresh(message, from: client, key: key)
            case .createPermission: createPermission(message, from: client, key: key)
            case .channelBind: channelBind(message, from: client, key: key)
            default: break
            }
        case (.indication, .send):
            handleSend(message, from: client)
        default:
            break
        }
    }

    /// Long-term credential check (RFC 5389 §10.2): challenge with REALM +
    /// NONCE when there is no MESSAGE-INTEGRITY, verify it otherwise. Returns
    /// the key to sign the response with, or nil after sending an error.
    private func authenticate(_ message: STUNMessage, raw: [UInt8], from client: ClientKey) -> [UInt8]? {
        let attributes = STUNMessage.AttributeType.self
        guard message.attribute(attributes.messageIntegrity) != nil,
              let username = message.string(attributes.username),
              let realm = message.string(attributes.realm),
              let nonce = message.string(attributes.nonce) else {
            sendError(401, "Unauthorized", to: message, client: client, challenge: true)
            return nil
        }
        guard nonces.contains(nonce) else {
            sendError(438, "Stale Nonce", to: message, client: client, challenge: true)
            return nil
        }
        guard realm == configuration.credentials.realm,
              let password = configuration.credentials.password(forValidUsername: username) else {
            sendError(401, "Unauthorized", to: message, client: client, challenge: true)
            return nil
        }
        let key = STUNMessage.longTermKey(username: username, realm: realm, password: password)
        guard STUNMessage.verifyIntegrity(raw: raw, key: key) else {
            sendError(401, "Unauthorized", to: message, client: client, challenge: true)
            return nil
        }
        return key
    }

    private func freshNonce() -> String {
        if nonces.count > 1024 { nonces.removeAll() }
        let nonce = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        nonces.insert(nonce)
        return nonce
    }

    private func sendError(_ code: Int, _ reason: String, to request: STUNMessage, client: ClientKey,
                           challenge: Bool = false, key: [UInt8]? = nil) {
        var response = STUNMessage(method: request.method, messageClass: .error, transactionID: request.transactionID)
        response.addError(code, reason: reason)
        if challenge {
            response.add(STUNMessage.AttributeType.realm, string: configuration.credentials.realm)
            response.add(STUNMessage.AttributeType.nonce, string: freshNonce())
        }
        response.add(STUNMessage.AttributeType.software, string: configuration.software)
        sendToClient(client, response.encode(integrityKey: key, fingerprint: true))
    }

    private func sendSuccess(_ response: STUNMessage, to client: ClientKey, key: [UInt8]) {
        var response = response
        response.add(STUNMessage.AttributeType.software, string: configuration.software)
        sendToClient(client, response.encode(integrityKey: key, fingerprint: true))
    }

    // MARK: - Allocate / Refresh

    private func allocate(_ message: STUNMessage, from client: ClientKey, key: [UInt8]) {
        let attributes = STUNMessage.AttributeType.self
        // RFC 5766 §6.2: only UDP relays (17); anything else is 442.
        guard let transport = message.attribute(attributes.requestedTransport), transport.count == 4, transport[0] == 17 else {
            sendError(442, "Unsupported Transport Protocol", to: message, client: client, key: key)
            return
        }
        if allocations[client] != nil {
            sendError(437, "Allocation Mismatch", to: message, client: client, key: key)
            return
        }
        guard let port = configuration.relayPorts.first(where: { !usedRelayPorts.contains($0) }),
              let bindAddress = SocketAddress(host: "0.0.0.0", port: port),
              let relayFD = try? Sockets.udp(bind: bindAddress) else {
            sendError(508, "Insufficient Capacity", to: message, client: client, key: key)
            return
        }
        Sockets.setNonBlocking(relayFD)
        usedRelayPorts.insert(port)
        let lifetime = clampLifetime(message.uint32(attributes.lifetime))
        guard let relayAddress = SocketAddress(host: configuration.relayHost, port: port) else {
            close(relayFD)
            usedRelayPorts.remove(port)
            sendError(500, "Server Error", to: message, client: client, key: key)
            return
        }
        let allocation = Allocation(
            client: client, relayFD: relayFD, relayAddress: relayAddress,
            expires: Date().addingTimeInterval(TimeInterval(lifetime)),
            username: message.string(attributes.username) ?? ""
        )
        allocations[client] = allocation
        allocationsByRelayFD[relayFD] = allocation
        statsLock.lock(); stats.allocations += 1; statsLock.unlock()
        log?("allocate \(client.address) -> relay \(relayAddress) lifetime \(lifetime)s")

        var response = STUNMessage(method: .allocate, messageClass: .success, transactionID: message.transactionID)
        response.addXORAddress(attributes.xorRelayedAddress, relayAddress)
        response.add(attributes.lifetime, uint32: lifetime)
        response.addXORAddress(attributes.xorMappedAddress, client.address)
        sendSuccess(response, to: client, key: key)
    }

    private func refresh(_ message: STUNMessage, from client: ClientKey, key: [UInt8]) {
        let attributes = STUNMessage.AttributeType.self
        guard let allocation = allocations[client] else {
            sendError(437, "Allocation Mismatch", to: message, client: client, key: key)
            return
        }
        let requested = message.uint32(attributes.lifetime)
        var response = STUNMessage(method: .refresh, messageClass: .success, transactionID: message.transactionID)
        if requested == 0 {
            release(allocation)
            response.add(attributes.lifetime, uint32: 0)
        } else {
            let lifetime = clampLifetime(requested)
            allocation.expires = Date().addingTimeInterval(TimeInterval(lifetime))
            response.add(attributes.lifetime, uint32: lifetime)
        }
        sendSuccess(response, to: client, key: key)
    }

    private func clampLifetime(_ requested: UInt32?) -> UInt32 {
        guard let requested, requested > 0 else { return configuration.defaultLifetime }
        return min(max(requested, configuration.defaultLifetime), configuration.maxLifetime)
    }

    private func release(_ allocation: Allocation) {
        allocations[allocation.client] = nil
        allocationsByRelayFD[allocation.relayFD] = nil
        usedRelayPorts.remove(allocation.relayAddress.port)
        close(allocation.relayFD)
        log?("release \(allocation.client.address)")
    }

    // MARK: - Permissions / channels

    private func createPermission(_ message: STUNMessage, from client: ClientKey, key: [UInt8]) {
        let attributes = STUNMessage.AttributeType.self
        guard let allocation = allocations[client] else {
            sendError(437, "Allocation Mismatch", to: message, client: client, key: key)
            return
        }
        let peers = message.xorAddresses(attributes.xorPeerAddress)
        guard !peers.isEmpty else {
            sendError(400, "Bad Request", to: message, client: client, key: key)
            return
        }
        let expiry = Date().addingTimeInterval(Self.permissionLifetime)
        for peer in peers { allocation.permissions[peer.addressBytes] = expiry }
        let response = STUNMessage(method: .createPermission, messageClass: .success, transactionID: message.transactionID)
        sendSuccess(response, to: client, key: key)
    }

    private func channelBind(_ message: STUNMessage, from client: ClientKey, key: [UInt8]) {
        let attributes = STUNMessage.AttributeType.self
        guard let allocation = allocations[client] else {
            sendError(437, "Allocation Mismatch", to: message, client: client, key: key)
            return
        }
        guard let raw = message.attribute(attributes.channelNumber), raw.count == 4,
              let peer = message.xorAddress(attributes.xorPeerAddress) else {
            sendError(400, "Bad Request", to: message, client: client, key: key)
            return
        }
        let channel = STUNMessage.readUInt16(raw, at: 0)
        guard (0x4000...0x7FFF).contains(channel) else {
            sendError(400, "Bad Request", to: message, client: client, key: key)
            return
        }
        // A number bound to another peer, or a peer bound to another number,
        // is a conflict (RFC 5766 §11.2).
        if let existing = allocation.channelsByNumber[channel], existing.peer != peer {
            sendError(400, "Bad Request", to: message, client: client, key: key)
            return
        }
        if let existing = allocation.channelsByPeer[peer], existing != channel {
            sendError(400, "Bad Request", to: message, client: client, key: key)
            return
        }
        let expiry = Date().addingTimeInterval(Self.channelLifetime)
        allocation.channelsByNumber[channel] = (peer, expiry)
        allocation.channelsByPeer[peer] = channel
        allocation.permissions[peer.addressBytes] = Date().addingTimeInterval(Self.permissionLifetime)
        let response = STUNMessage(method: .channelBind, messageClass: .success, transactionID: message.transactionID)
        sendSuccess(response, to: client, key: key)
    }

    // MARK: - Relaying

    private func handleSend(_ message: STUNMessage, from client: ClientKey) {
        let attributes = STUNMessage.AttributeType.self
        guard let allocation = allocations[client],
              let peer = message.xorAddress(attributes.xorPeerAddress),
              let data = message.attribute(attributes.data),
              let permitted = allocation.permissions[peer.addressBytes], permitted > Date() else { return }
        Sockets.send(allocation.relayFD, data, to: peer)
        statsLock.lock(); stats.relayedBytes += data.count; statsLock.unlock()
    }

    private func handleChannelData(channel: UInt16, data: [UInt8], from client: ClientKey) {
        guard let allocation = allocations[client],
              let bound = allocation.channelsByNumber[channel], bound.expires > Date() else { return }
        Sockets.send(allocation.relayFD, data, to: bound.peer)
        statsLock.lock(); stats.relayedBytes += data.count; statsLock.unlock()
    }

    private func relayToClient(_ allocation: Allocation, _ data: [UInt8], from peer: SocketAddress) {
        let now = Date()
        if let channel = allocation.channelsByPeer[peer],
           let bound = allocation.channelsByNumber[channel], bound.expires > now {
            sendToClient(allocation.client, ChannelData.encode(channel: channel, data: data, padForStream: allocation.client.tcpFD >= 0))
        } else if let permitted = allocation.permissions[peer.addressBytes], permitted > now {
            var indication = STUNMessage(method: .data, messageClass: .indication)
            indication.addXORAddress(STUNMessage.AttributeType.xorPeerAddress, peer)
            indication.add(STUNMessage.AttributeType.data, data)
            sendToClient(allocation.client, indication.encode(fingerprint: true))
        } else {
            return
        }
        statsLock.lock(); stats.relayedBytes += data.count; statsLock.unlock()
    }

    private func sweepExpired() {
        let now = Date()
        for allocation in Array(allocations.values) {
            if allocation.expires < now {
                release(allocation)
                continue
            }
            allocation.permissions = allocation.permissions.filter { $0.value > now }
            for (number, bound) in allocation.channelsByNumber where bound.expires < now {
                allocation.channelsByNumber[number] = nil
                allocation.channelsByPeer[bound.peer] = nil
            }
        }
    }
}
