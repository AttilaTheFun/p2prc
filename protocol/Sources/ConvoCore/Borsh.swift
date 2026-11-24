import ConvoFoundation

// borsh (Appendix A.1): little-endian fixed-width integers, `u32`
// length-prefixed vectors and strings, `Option` as 0x00 / 0x01 ‖ T, fixed
// arrays raw, enums as a u8 tag ‖ payload. One valid encoding per value:
// these are the canonical bytes every hash and signature is over.

public struct BorshWriter {
    public private(set) var bytes: [UInt8] = []
    public init() {}

    public mutating func u8(_ v: UInt8) { bytes.append(v) }
    public mutating func u16(_ v: UInt16) { bytes.append(contentsOf: withUnsafeBytes(of: v.littleEndian, Array.init)) }
    public mutating func u32(_ v: UInt32) { bytes.append(contentsOf: withUnsafeBytes(of: v.littleEndian, Array.init)) }
    public mutating func u64(_ v: UInt64) { bytes.append(contentsOf: withUnsafeBytes(of: v.littleEndian, Array.init)) }
    public mutating func bool(_ v: Bool) { bytes.append(v ? 1 : 0) }
    /// A fixed-size array: raw, no length.
    public mutating func fixed(_ v: [UInt8]) { bytes.append(contentsOf: v) }
    public mutating func fixed(_ v: Hash32) { bytes.append(contentsOf: v.bytes) }
    /// A variable-size vector: u32 length then the items.
    public mutating func vec(_ v: [UInt8]) { u32(UInt32(v.count)); bytes.append(contentsOf: v) }
    public mutating func string(_ v: String) { vec(Array(v.utf8)) }
    public mutating func vec<T>(_ items: [T], _ each: (inout BorshWriter, T) -> Void) {
        u32(UInt32(items.count))
        for item in items { each(&self, item) }
    }
    public mutating func option<T>(_ value: T?, _ each: (inout BorshWriter, T) -> Void) {
        if let value { u8(1); each(&self, value) } else { u8(0) }
    }
}

public struct BorshError: Error, Equatable, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

public struct BorshReader {
    private let bytes: [UInt8]
    public private(set) var offset = 0
    public init(_ bytes: [UInt8]) { self.bytes = bytes }

    public var isAtEnd: Bool { offset == bytes.count }
    public var remaining: Int { bytes.count - offset }

    private mutating func take(_ n: Int) throws -> ArraySlice<UInt8> {
        guard n >= 0, offset + n <= bytes.count else { throw BorshError("unexpected end of borsh input") }
        defer { offset += n }
        return bytes[offset..<offset + n]
    }

    public mutating func u8() throws -> UInt8 { try take(1).first! }
    public mutating func u16() throws -> UInt16 { try take(2).reversed().reduce(0) { $0 << 8 | UInt16($1) } }
    public mutating func u32() throws -> UInt32 { try take(4).reversed().reduce(0) { $0 << 8 | UInt32($1) } }
    public mutating func u64() throws -> UInt64 { try take(8).reversed().reduce(0) { $0 << 8 | UInt64($1) } }
    public mutating func bool() throws -> Bool {
        let b = try u8()
        guard b <= 1 else { throw BorshError("invalid bool \(b)") }
        return b == 1
    }
    public mutating func fixed(_ n: Int) throws -> [UInt8] { Array(try take(n)) }
    public mutating func hash32() throws -> Hash32 { Hash32(try fixed(32)) }
    /// A vector's length, checked against what is left before it becomes an
    /// `Int`: on a 32-bit target (wasm) a garbage length above `Int.max`
    /// would trap in the conversion instead of throwing.
    private mutating func length() throws -> Int {
        let n = try u32()
        guard n <= UInt32(clamping: remaining) else { throw BorshError("vector length \(n) exceeds input") }
        return Int(n)
    }
    public mutating func vec() throws -> [UInt8] { Array(try take(try length())) }
    public mutating func string() throws -> String {
        guard let s = String(bytes: try vec(), encoding: .utf8) else { throw BorshError("invalid utf8") }
        return s
    }
    public mutating func vec<T>(_ each: (inout BorshReader) throws -> T) throws -> [T] {
        let n = try length()
        var items: [T] = []
        items.reserveCapacity(n)
        for _ in 0..<n { items.append(try each(&self)) }
        return items
    }
    public mutating func option<T>(_ each: (inout BorshReader) throws -> T) throws -> T? {
        let tag = try u8()
        switch tag {
        case 0: return nil
        case 1: return try each(&self)
        default: throw BorshError("invalid option tag \(tag)")
        }
    }
    /// The whole input must have been consumed: canonical bytes carry nothing extra.
    public func finish() throws {
        guard isAtEnd else { throw BorshError("\(remaining) trailing bytes") }
    }
}

/// A value with one canonical borsh encoding.
public protocol BorshCodable {
    func borshEncode(into writer: inout BorshWriter)
    init(borshFrom reader: inout BorshReader) throws
}

extension BorshCodable {
    public var borsh: [UInt8] {
        var w = BorshWriter()
        borshEncode(into: &w)
        return w.bytes
    }

    public static func decode(_ bytes: [UInt8]) throws -> Self {
        var r = BorshReader(bytes)
        let value = try Self(borshFrom: &r)
        try r.finish()
        return value
    }
}

/// 32 bytes: a hash, a key, a salt.
public struct Hash32: Hashable, Sendable, Comparable, CustomStringConvertible {
    public let bytes: [UInt8]

    public init(_ bytes: [UInt8]) {
        precondition(bytes.count == 32, "Hash32 needs 32 bytes, got \(bytes.count)")
        self.bytes = bytes
    }

    public init?(hex: String) {
        guard let b = [UInt8](hex: hex), b.count == 32 else { return nil }
        self.bytes = b
    }

    public static let zero = Hash32([UInt8](repeating: 0, count: 32))

    /// Lexicographic, as bytes: the tie-breaker in canonical order (§4).
    public static func < (a: Hash32, b: Hash32) -> Bool { a.bytes.lexicographicallyPrecedes(b.bytes) }

    public var hex: String { bytes.hex }
    public var description: String { hex }
}

extension Array where Element == UInt8 {
    public var hex: String {
        let digits = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(count * 2)
        for byte in self { out.append(digits[Int(byte >> 4)]); out.append(digits[Int(byte & 0x0f)]) }
        return String(decoding: out, as: UTF8.self)
    }

    public init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = UInt8(String(UnicodeScalar(chars[i])), radix: 16),
                  let lo = UInt8(String(UnicodeScalar(chars[i + 1])), radix: 16) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        self = out
    }
}
