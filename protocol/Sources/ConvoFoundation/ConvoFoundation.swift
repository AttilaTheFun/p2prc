// The Foundation the node's modules (ConvoCore, ConvoNet, ConvoNodeCore)
// build on. On WebAssembly that's swift-foundation's FoundationEssentials
// alone: full Foundation brings ICU's locale data, some 30 MB a node never
// reads, into a module a Cloudflare Worker loads into 128 MB. Everywhere
// else it's Foundation, as before. This file is the only place the choice
// is made. The apps' Bazel build for the web sets CONVO_ISOMER_FOUNDATION:
// it is on Isomer's Swift SDK, whose Foundation is FoundationEssentials
// with Isomer's additions, so it takes Foundation there too.
#if os(WASI) && !CONVO_ISOMER_FOUNDATION
@_exported import FoundationEssentials

/// WebAssembly here has one thread: there is nothing to exclude.
public final class NSLock: @unchecked Sendable {
    public init() {}
    public func lock() {}
    public func unlock() {}
    public func withLock<R>(_ body: () throws -> R) rethrows -> R { try body() }
}
#else
@_exported import Foundation
#endif
