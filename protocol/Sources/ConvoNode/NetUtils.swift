import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// The connected-UDP-socket trick for "which address do I reach the internet
/// from" — the same one libraries/p2prc's NetUtils uses, repeated here so the
/// node doesn't pull the Apple-flavoured library in for one function.
public enum NetUtils {
    public static func primaryIPv4Address() -> String? {
        #if canImport(Glibc)
        let fd = socket(AF_INET, Int32(SOCK_DGRAM.rawValue), 0)
        #else
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        #endif
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var remote = sockaddr_in()
        remote.sin_family = sa_family_t(AF_INET)
        remote.sin_port = UInt16(53).bigEndian
        inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr)
        let connected = withUnsafePointer(to: &remote) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard connected == 0 else { return nil }
        var local = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard ok == 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        _ = inet_ntop(AF_INET, &local.sin_addr, &buffer, socklen_t(buffer.count))
        return String(cString: buffer)
    }
}
