import Foundation
import ConvoNet
#if canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#elseif canImport(Darwin)
import Darwin
#endif

/// The same minimal HTTP/1.1 server as `SimpleHTTPServer`, on POSIX sockets:
/// what the Linux node and the Android host run, where Apple's Network
/// framework doesn't exist. Same request/response types, same handler
/// contract, so `Serving` is oblivious to which one is underneath.
///
/// An accept loop on one thread, one short-lived thread per connection:
/// requests here are a few hundred bytes of signaling or a site file, and
/// the server never sees more than a handful of clients at once.
public final class PosixHTTPServer: @unchecked Sendable {
    public typealias RequestHandler = @Sendable (HTTPRequest) -> HTTPResponse

    public let port: UInt16
    private let handler: RequestHandler
    private var listenFD: Int32 = -1
    private var running = false

    public init(port: UInt16, requestHandler: @escaping RequestHandler) throws {
        self.port = port
        self.handler = requestHandler
        #if canImport(Glibc)
        let streamType = Int32(SOCK_STREAM.rawValue)
        #else
        let streamType = SOCK_STREAM
        #endif
        let fd = socket(AF_INET6, streamType, 0)
        guard fd >= 0 else { throw PosixHTTPError("socket") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        // Dual-stack: a v6 wildcard listener also takes v4 clients.
        var zero: Int32 = 0
        setsockopt(fd, Int32(IPPROTO_IPV6), IPV6_V6ONLY, &zero, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in6()
        address.sin6_family = sa_family_t(AF_INET6)
        address.sin6_port = port.bigEndian
        address.sin6_addr = in6addr_any
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
        }
        guard bound == 0, listen(fd, 64) == 0 else {
            let error = PosixHTTPError("bind/listen port \(port)")
            close(fd)
            throw error
        }
        listenFD = fd
    }

    public func start() {
        running = true
        let thread = Thread { [self] in self.acceptLoop() }
        thread.name = "p2prc-http"
        thread.start()
    }

    public func stop() {
        running = false
        close(listenFD)
    }

    private func acceptLoop() {
        while running {
            var storage = sockaddr_storage()
            var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let fd = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(listenFD, $0, &length) }
            }
            guard fd >= 0 else {
                if !running { return }
                continue
            }
            let peer = Self.describe(&storage)
            let thread = Thread { [self] in self.serve(fd: fd, peer: peer) }
            thread.start()
        }
    }

    /// "host:port" of the caller; v4-mapped v6 rendered as the v4 it is.
    private static func describe(_ storage: inout sockaddr_storage) -> String {
        let family = Int32(storage.ss_family)
        if family == AF_INET6 {
            let sa = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            }
            let raw = withUnsafeBytes(of: sa.sin6_addr) { Array($0) }
            let port = UInt16(bigEndian: sa.sin6_port)
            if raw[0..<10].allSatisfy({ $0 == 0 }), raw[10] == 0xFF, raw[11] == 0xFF {
                return raw[12..<16].map(String.init).joined(separator: ".") + ":\(port)"
            }
            var copy = sa.sin6_addr
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            _ = inet_ntop(AF_INET6, &copy, &buffer, socklen_t(buffer.count))
            return String(cString: buffer) + ":\(port)"
        }
        if family == AF_INET {
            let sa = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            }
            let raw = withUnsafeBytes(of: sa.sin_addr) { Array($0) }
            return raw.map(String.init).joined(separator: ".") + ":\(UInt16(bigEndian: sa.sin_port))"
        }
        return ""
    }

    private func serve(fd: Int32, peer: String) {
        defer { close(fd) }
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var buffer = [UInt8](repeating: 0, count: 65536)
        var received: [UInt8] = []
        var request: HTTPRequest?
        while request == nil {
            let count = recv(fd, &buffer, buffer.count, 0)
            guard count > 0 else { return }
            received += buffer[0..<count]
            guard received.count < 1 << 20 else { return }
            request = HTTPParser.parse(received, peer: peer)
        }
        guard let request else { return }
        let response = handler(request)
        let bytes = HTTPParser.serialize(response)
        var offset = 0
        while offset < bytes.count {
            let sent = bytes.withUnsafeBufferPointer { buf -> Int in
                #if canImport(Glibc) || canImport(Android)
                return send(fd, buf.baseAddress! + offset, buf.count - offset, Int32(MSG_NOSIGNAL))
                #else
                return send(fd, buf.baseAddress! + offset, buf.count - offset, 0)
                #endif
            }
            if sent <= 0 { return }
            offset += sent
        }
    }
}

public struct PosixHTTPError: Error, CustomStringConvertible {
    public let description: String
    init(_ what: String) { description = "\(what): \(String(cString: strerror(errno)))" }
}

/// The request-line/header/body parsing and response serialization both
/// servers share.
package enum HTTPParser {
    /// A complete request from the bytes so far, or nil to keep reading.
    static func parse(_ bytes: [UInt8], peer: String) -> HTTPRequest? {
        let separator: [UInt8] = [13, 10, 13, 10]
        guard let headerEnd = firstRange(of: separator, in: bytes) else { return nil }
        guard let head = String(bytes: bytes[0..<headerEnd], encoding: .utf8) else { return nil }
        let lines = head.components(separatedBy: "\r\n")
        let parts = (lines.first ?? "").split(separator: " ")
        let method = parts.count > 0 ? String(parts[0]) : "GET"
        let path = parts.count > 1 ? String(parts[1]) : "/"
        var headers: [String: String] = [:]
        var contentLength = 0
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
            if name == "content-length" { contentLength = Int(value) ?? 0 }
        }
        let bodyStart = headerEnd + separator.count
        guard bytes.count - bodyStart >= contentLength else { return nil }
        let body = Data(bytes[bodyStart..<(bodyStart + contentLength)])
        return HTTPRequest(method: method, path: path, body: body, headers: headers, peer: peer)
    }

    package static func serialize(_ response: HTTPResponse) -> [UInt8] {
        let statusText: String
        switch response.status {
        case 200: statusText = "OK"
        case 204: statusText = "No Content"
        case 400: statusText = "Bad Request"
        case 404: statusText = "Not Found"
        default: statusText = "Error"
        }
        var head = "HTTP/1.1 \(response.status) \(statusText)\r\n"
        head += "Content-Type: \(response.contentType)\r\n"
        head += "Content-Length: \(response.body.count)\r\n"
        head += "Cache-Control: no-store\r\n"
        head += "Access-Control-Allow-Origin: *\r\n"
        head += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        head += "Access-Control-Allow-Headers: Content-Type, \(NodeAPI.authHeader)\r\n"
        head += "Access-Control-Max-Age: 86400\r\n"
        head += "Connection: close\r\n\r\n"
        return Array(head.utf8) + Array(response.body)
    }

    private static func firstRange(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard haystack.count >= needle.count else { return nil }
        for i in 0...(haystack.count - needle.count) where haystack[i] == needle[0] {
            if Array(haystack[i..<(i + needle.count)]) == needle { return i }
        }
        return nil
    }
}

#if !canImport(Network)
/// Where Network.framework is absent, the POSIX server IS SimpleHTTPServer.
public typealias SimpleHTTPServer = PosixHTTPServer
#endif
