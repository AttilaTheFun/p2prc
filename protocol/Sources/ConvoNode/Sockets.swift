import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#elseif canImport(Darwin)
import Darwin
#endif

/// An IPv4 or IPv6 address + port, in the forms the wire, the kernel, and a
/// log line each want. Value type; the kernel form is derived on demand.
public struct SocketAddress: Hashable, CustomStringConvertible {
    /// 4 or 16 raw bytes, network order.
    public let addressBytes: [UInt8]
    public let port: UInt16

    public init(addressBytes: [UInt8], port: UInt16) {
        self.addressBytes = addressBytes
        self.port = port
    }

    public var isIPv6: Bool { addressBytes.count == 16 }

    /// Parses "1.2.3.4" or "::1" (no brackets, no port).
    public init?(host: String, port: UInt16) {
        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            self.init(addressBytes: withUnsafeBytes(of: v4) { Array($0) }, port: port)
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, host, &v6) == 1 {
            self.init(addressBytes: withUnsafeBytes(of: v6) { Array($0) }, port: port)
            return
        }
        return nil
    }

    public var host: String {
        if isIPv6 {
            var raw = in6_addr()
            withUnsafeMutableBytes(of: &raw) { $0.copyBytes(from: addressBytes) }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            _ = inet_ntop(AF_INET6, &raw, &buffer, socklen_t(buffer.count))
            return String(cString: buffer)
        }
        return addressBytes.map(String.init).joined(separator: ".")
    }

    public var description: String { isIPv6 ? "[\(host)]:\(port)" : "\(host):\(port)" }

    /// The kernel form. IPv4 addresses are handed to the kernel as-is; a
    /// dual-stack (v6) socket needs them mapped, see `mappedToIPv6`.
    func withSockaddr<T>(_ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
        if isIPv6 {
            var sa = sockaddr_in6()
            sa.sin6_family = sa_family_t(AF_INET6)
            sa.sin6_port = port.bigEndian
            withUnsafeMutableBytes(of: &sa.sin6_addr) { $0.copyBytes(from: addressBytes) }
            return withUnsafePointer(to: &sa) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        }
        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        withUnsafeMutableBytes(of: &sa.sin_addr) { $0.copyBytes(from: addressBytes) }
        return withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
    }

    /// Reads a sockaddr the kernel filled in. ::ffff:a.b.c.d comes back as
    /// the IPv4 it is, so a v4 client of a dual-stack socket is answered in
    /// the family it asked from.
    init?(storage: UnsafePointer<sockaddr_storage>) {
        let family = Int32(storage.pointee.ss_family)
        if family == AF_INET {
            let sa = storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            self.init(addressBytes: withUnsafeBytes(of: sa.sin_addr) { Array($0) }, port: UInt16(bigEndian: sa.sin_port))
        } else if family == AF_INET6 {
            let sa = storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            let raw = withUnsafeBytes(of: sa.sin6_addr) { Array($0) }
            let port = UInt16(bigEndian: sa.sin6_port)
            if raw[0..<10].allSatisfy({ $0 == 0 }), raw[10] == 0xFF, raw[11] == 0xFF {
                self.init(addressBytes: Array(raw[12..<16]), port: port)
            } else {
                self.init(addressBytes: raw, port: port)
            }
        } else {
            return nil
        }
    }
}

/// Thin, explicit POSIX wrappers. Errors are thrown with errno text so a
/// bind failure names the port and the reason, which is most of debugging.
public struct SocketError: Error, CustomStringConvertible {
    public let description: String
    init(_ what: String) {
        self.description = "\(what): \(String(cString: strerror(errno))) (errno \(errno))"
    }
}

public enum Sockets {
    // Glibc models the socket type as an enum; Darwin and Bionic as Int32.
    #if canImport(Glibc)
    static let datagramType = Int32(SOCK_DGRAM.rawValue)
    static let streamType = Int32(SOCK_STREAM.rawValue)
    #else
    static let datagramType = SOCK_DGRAM
    static let streamType = SOCK_STREAM
    #endif

    public static func udp(bind address: SocketAddress) throws -> Int32 {
        let fd = socket(address.isIPv6 ? AF_INET6 : AF_INET, Sockets.datagramType, 0)
        guard fd >= 0 else { throw SocketError("socket(udp)") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        let bound = address.withSockaddr { bind(fd, $0, $1) }
        guard bound == 0 else {
            let error = SocketError("bind udp \(address)")
            close(fd)
            throw error
        }
        return fd
    }

    static func tcpListener(bind address: SocketAddress, backlog: Int32 = 64) throws -> Int32 {
        let fd = socket(address.isIPv6 ? AF_INET6 : AF_INET, Sockets.streamType, 0)
        guard fd >= 0 else { throw SocketError("socket(tcp)") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        let bound = address.withSockaddr { bind(fd, $0, $1) }
        guard bound == 0, listen(fd, backlog) == 0 else {
            let error = SocketError("bind/listen tcp \(address)")
            close(fd)
            throw error
        }
        return fd
    }

    static func setNonBlocking(_ fd: Int32) {
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
    }

    public static func localAddress(_ fd: Int32) -> SocketAddress? {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard ok == 0 else { return nil }
        return withUnsafePointer(to: &storage) { SocketAddress(storage: $0) }
    }

    /// One datagram, with its sender.
    public static func receive(_ fd: Int32, into buffer: inout [UInt8]) -> (count: Int, from: SocketAddress)? {
        var storage = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let received = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                recvfrom(fd, &buffer, buffer.count, 0, sa, &length)
            }
        }
        guard received > 0, let from = withUnsafePointer(to: &storage, { SocketAddress(storage: $0) }) else { return nil }
        return (received, from)
    }

    public static func send(_ fd: Int32, _ bytes: [UInt8], to address: SocketAddress) {
        _ = address.withSockaddr { sa, length in
            bytes.withUnsafeBufferPointer { sendto(fd, $0.baseAddress!, $0.count, 0, sa, length) }
        }
    }

    static func write(_ fd: Int32, _ bytes: [UInt8]) {
        var offset = 0
        while offset < bytes.count {
            let sent = bytes.withUnsafeBufferPointer {
                #if canImport(Glibc) || canImport(Android)
                Glibc_send(fd, $0.baseAddress! + offset, $0.count - offset)
                #else
                Darwin.send(fd, $0.baseAddress! + offset, $0.count - offset, 0)
                #endif
            }
            if sent <= 0 { return }
            offset += sent
        }
    }
}

#if canImport(Glibc)
@inline(__always) private func Glibc_send(_ fd: Int32, _ p: UnsafeRawPointer, _ n: Int) -> Int {
    Glibc.send(fd, p, n, Int32(MSG_NOSIGNAL))
}
#elseif canImport(Android)
@inline(__always) private func Glibc_send(_ fd: Int32, _ p: UnsafeRawPointer, _ n: Int) -> Int {
    Android.send(fd, p, n, Int32(MSG_NOSIGNAL))
}
#endif
