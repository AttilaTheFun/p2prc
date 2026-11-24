import Crypto
import Foundation

/// The STUN wire format (RFC 5389 / RFC 8489), plus the TURN methods and
/// attributes layered on it (RFC 5766 / RFC 8656).
///
/// Pure codec: bytes in, values out, and back. No sockets, no policy. Both
/// the relay server and any client-side probe share it, which is how the
/// server gets tested in-process without a second implementation.
public struct STUNMessage: Equatable {
    public static let magic: UInt32 = 0x2112_A442
    public static let headerLength = 20

    public enum Class: UInt16 {
        case request = 0b00
        case indication = 0b01
        case success = 0b10
        case error = 0b11
    }

    public enum Method: UInt16 {
        case binding = 0x001
        case allocate = 0x003
        case refresh = 0x004
        case send = 0x006
        case data = 0x007
        case createPermission = 0x008
        case channelBind = 0x009
    }

    public var method: Method
    public var messageClass: Class
    public var transactionID: [UInt8]   // 12 bytes
    public var attributes: [Attribute]

    public struct Attribute: Equatable {
        public var type: UInt16
        public var value: [UInt8]
        public init(type: UInt16, value: [UInt8]) {
            self.type = type
            self.value = value
        }
    }

    // Attribute types (RFC 8489 §18.3, RFC 8656 §18).
    public enum AttributeType {
        public static let mappedAddress: UInt16 = 0x0001
        public static let username: UInt16 = 0x0006
        public static let messageIntegrity: UInt16 = 0x0008
        public static let errorCode: UInt16 = 0x0009
        public static let unknownAttributes: UInt16 = 0x000A
        public static let channelNumber: UInt16 = 0x000C
        public static let lifetime: UInt16 = 0x000D
        public static let xorPeerAddress: UInt16 = 0x0012
        public static let data: UInt16 = 0x0013
        public static let realm: UInt16 = 0x0014
        public static let nonce: UInt16 = 0x0015
        public static let xorRelayedAddress: UInt16 = 0x0016
        public static let requestedAddressFamily: UInt16 = 0x0017
        public static let evenPort: UInt16 = 0x0018
        public static let requestedTransport: UInt16 = 0x0019
        public static let dontFragment: UInt16 = 0x001A
        public static let xorMappedAddress: UInt16 = 0x0020
        public static let reservationToken: UInt16 = 0x0022
        public static let software: UInt16 = 0x8022
        public static let alternateServer: UInt16 = 0x8023
        public static let fingerprint: UInt16 = 0x8028
    }

    public init(method: Method, messageClass: Class, transactionID: [UInt8]? = nil, attributes: [Attribute] = []) {
        self.method = method
        self.messageClass = messageClass
        self.transactionID = transactionID ?? Self.randomTransactionID()
        self.attributes = attributes
    }

    public static func randomTransactionID() -> [UInt8] {
        (0..<12).map { _ in UInt8.random(in: 0...255) }
    }

    // MARK: - Type field

    /// RFC 5389 §6: the method's 12 bits are interleaved with the two class
    /// bits (C1 at bit 8, C0 at bit 4).
    static func encodeType(method: UInt16, messageClass: UInt16) -> UInt16 {
        let m = method
        var type: UInt16 = 0
        type |= (m & 0x000F)
        type |= (m & 0x0070) << 1
        type |= (m & 0x0F80) << 2
        type |= (messageClass & 0x1) << 4
        type |= (messageClass & 0x2) << 7
        return type
    }

    static func decodeType(_ type: UInt16) -> (method: UInt16, messageClass: UInt16) {
        let method = (type & 0x000F) | ((type >> 1) & 0x0070) | ((type >> 2) & 0x0F80)
        let messageClass = ((type >> 4) & 0x1) | ((type >> 7) & 0x2)
        return (method, messageClass)
    }

    // MARK: - Parsing

    /// Whether `bytes` begin a STUN message (as opposed to ChannelData or
    /// something else sharing the socket). RFC 5389 §6: top two bits zero,
    /// magic cookie present.
    public static func looksLikeSTUN(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= headerLength, bytes[0] & 0xC0 == 0 else { return false }
        return readUInt32(bytes, at: 4) == magic
    }

    /// The total length a STUN message starting at `bytes` occupies, or nil
    /// if the header is incomplete. For stream transports.
    public static func framedLength(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= headerLength else { return nil }
        return headerLength + Int(readUInt16(bytes, at: 2))
    }

    public static func parse(_ bytes: [UInt8]) -> STUNMessage? {
        guard looksLikeSTUN(bytes) else { return nil }
        let (rawMethod, rawClass) = decodeType(readUInt16(bytes, at: 0))
        let length = Int(readUInt16(bytes, at: 2))
        guard length % 4 == 0, bytes.count >= headerLength + length,
              let method = Method(rawValue: rawMethod),
              let messageClass = Class(rawValue: rawClass) else { return nil }
        let transactionID = Array(bytes[8..<20])
        var attributes: [Attribute] = []
        var offset = headerLength
        let end = headerLength + length
        while offset + 4 <= end {
            let type = readUInt16(bytes, at: offset)
            let valueLength = Int(readUInt16(bytes, at: offset + 2))
            let valueStart = offset + 4
            guard valueStart + valueLength <= end else { return nil }
            attributes.append(Attribute(type: type, value: Array(bytes[valueStart..<(valueStart + valueLength)])))
            offset = valueStart + ((valueLength + 3) & ~3)
        }
        return STUNMessage(method: method, messageClass: messageClass, transactionID: transactionID, attributes: attributes)
    }

    // MARK: - Encoding

    /// Serializes the message. With `integrityKey`, appends MESSAGE-INTEGRITY
    /// (HMAC-SHA1 over everything before it, with the header length counting
    /// the integrity attribute — RFC 5389 §15.4); `fingerprint` then appends
    /// FINGERPRINT over everything before it (§15.5).
    public func encode(integrityKey: [UInt8]? = nil, fingerprint: Bool = false) -> [UInt8] {
        var body: [UInt8] = []
        for attribute in attributes {
            Self.appendAttribute(&body, attribute)
        }
        var out = Self.header(method: method, messageClass: messageClass, transactionID: transactionID, length: body.count)
        out += body
        if let integrityKey {
            // Length must already include the 24-byte MI attribute when
            // the HMAC is computed.
            Self.writeUInt16(&out, at: 2, UInt16(body.count + 24))
            let mac = Self.hmacSHA1(key: integrityKey, data: out)
            Self.appendAttribute(&out, Attribute(type: AttributeType.messageIntegrity, value: mac))
        }
        if fingerprint {
            Self.writeUInt16(&out, at: 2, UInt16(out.count - Self.headerLength + 8))
            let crc = Self.crc32(out) ^ 0x5354_554E
            Self.appendAttribute(&out, Attribute(type: AttributeType.fingerprint, value: Self.bytes(crc)))
        }
        return out
    }

    private static func header(method: Method, messageClass: Class, transactionID: [UInt8], length: Int) -> [UInt8] {
        var out: [UInt8] = []
        let type = encodeType(method: method.rawValue, messageClass: messageClass.rawValue)
        out += bytes(type)
        out += bytes(UInt16(length))
        out += bytes(magic)
        out += transactionID
        return out
    }

    private static func appendAttribute(_ out: inout [UInt8], _ attribute: Attribute) {
        out += bytes(attribute.type)
        out += bytes(UInt16(attribute.value.count))
        out += attribute.value
        let padding = (4 - attribute.value.count % 4) % 4
        out += [UInt8](repeating: 0, count: padding)
    }

    // MARK: - Integrity verification

    /// Verifies MESSAGE-INTEGRITY against `key` on the raw bytes the message
    /// was parsed from. Attributes after MI (FINGERPRINT) are ignored, as
    /// the RFC requires.
    public static func verifyIntegrity(raw: [UInt8], key: [UInt8]) -> Bool {
        // Locate the MI attribute by walking the raw attributes.
        guard raw.count >= headerLength else { return false }
        let length = Int(readUInt16(raw, at: 2))
        var offset = headerLength
        let end = min(raw.count, headerLength + length)
        while offset + 4 <= end {
            let type = readUInt16(raw, at: offset)
            let valueLength = Int(readUInt16(raw, at: offset + 2))
            if type == AttributeType.messageIntegrity {
                guard valueLength == 20, offset + 24 <= raw.count else { return false }
                var covered = Array(raw[0..<offset])
                writeUInt16(&covered, at: 2, UInt16(offset - headerLength + 24))
                let expected = hmacSHA1(key: key, data: covered)
                let actual = Array(raw[(offset + 4)..<(offset + 24)])
                return constantTimeEqual(expected, actual)
            }
            offset += 4 + ((valueLength + 3) & ~3)
        }
        return false
    }

    /// RFC 5389 §15.4: the long-term credential key.
    public static func longTermKey(username: String, realm: String, password: String) -> [UInt8] {
        Array(Insecure.MD5.hash(data: Data((username + ":" + realm + ":" + password).utf8)))
    }

    static func hmacSHA1(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key))
        return Array(mac)
    }

    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    // MARK: - Attribute helpers

    public func attribute(_ type: UInt16) -> [UInt8]? {
        attributes.first { $0.type == type }?.value
    }

    public func attributes(_ type: UInt16) -> [[UInt8]] {
        attributes.filter { $0.type == type }.map(\.value)
    }

    public func string(_ type: UInt16) -> String? {
        attribute(type).flatMap { String(bytes: $0, encoding: .utf8) }
    }

    public func uint32(_ type: UInt16) -> UInt32? {
        guard let v = attribute(type), v.count == 4 else { return nil }
        return Self.readUInt32(v, at: 0)
    }

    public mutating func add(_ type: UInt16, _ value: [UInt8]) {
        attributes.append(Attribute(type: type, value: value))
    }

    public mutating func add(_ type: UInt16, string: String) {
        add(type, Array(string.utf8))
    }

    public mutating func add(_ type: UInt16, uint32: UInt32) {
        add(type, Self.bytes(uint32))
    }

    /// ERROR-CODE: class in the low 3 bits of byte 2, number in byte 3.
    public mutating func addError(_ code: Int, reason: String) {
        var value: [UInt8] = [0, 0, UInt8(code / 100), UInt8(code % 100)]
        value += Array(reason.utf8)
        add(AttributeType.errorCode, value)
    }

    public var errorCode: Int? {
        guard let v = attribute(AttributeType.errorCode), v.count >= 4 else { return nil }
        return Int(v[2] & 0x7) * 100 + Int(v[3])
    }

    // MARK: - Addresses

    /// XOR-encoded address attributes (XOR-MAPPED/PEER/RELAYED-ADDRESS):
    /// port XOR the magic's top half, address XOR magic (+ transaction id
    /// for IPv6).
    public mutating func addXORAddress(_ type: UInt16, _ address: SocketAddress) {
        var bytes: [UInt8] = [0, address.isIPv6 ? 0x02 : 0x01]
        bytes += Self.bytes(address.port ^ 0x2112)
        var mask = Self.bytes(Self.magic)
        if address.isIPv6 { mask += transactionID }
        let raw = address.addressBytes
        for i in 0..<raw.count { bytes.append(raw[i] ^ mask[i]) }
        add(type, bytes)
    }

    public func xorAddress(_ type: UInt16) -> SocketAddress? {
        attribute(type).flatMap { decodeXORAddress($0) }
    }

    public func xorAddresses(_ type: UInt16) -> [SocketAddress] {
        attributes(type).compactMap { decodeXORAddress($0) }
    }

    private func decodeXORAddress(_ v: [UInt8]) -> SocketAddress? {
        guard v.count >= 8 else { return nil }
        let family = v[1]
        let port = Self.readUInt16(v, at: 2) ^ 0x2112
        var mask = Self.bytes(Self.magic)
        if family == 0x02 { mask += transactionID }
        let length = family == 0x02 ? 16 : 4
        guard v.count >= 4 + length else { return nil }
        var raw: [UInt8] = []
        for i in 0..<length { raw.append(v[4 + i] ^ mask[i]) }
        return SocketAddress(addressBytes: raw, port: port)
    }

    // MARK: - Byte utilities

    static func readUInt16(_ b: [UInt8], at i: Int) -> UInt16 {
        UInt16(b[i]) << 8 | UInt16(b[i + 1])
    }

    static func readUInt32(_ b: [UInt8], at i: Int) -> UInt32 {
        UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
    }

    static func writeUInt16(_ b: inout [UInt8], at i: Int, _ v: UInt16) {
        b[i] = UInt8(v >> 8)
        b[i + 1] = UInt8(v & 0xFF)
    }

    static func bytes(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
    static func bytes(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    static func crc32(_ bytes: [UInt8]) -> UInt32 {
        var c: UInt32 = 0xFFFF_FFFF
        for b in bytes { c = crcTable[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8) }
        return c ^ 0xFFFF_FFFF
    }
}

/// ChannelData framing (RFC 5766 §11.4): channel number, length, payload.
/// Channel numbers live in 0x4000–0x7FFF, which is also how the first byte
/// distinguishes them from STUN (whose top two bits are zero).
public enum ChannelData {
    public static func looksLikeChannelData(_ bytes: [UInt8]) -> Bool {
        bytes.count >= 4 && bytes[0] & 0xC0 == 0x40
    }

    public static func encode(channel: UInt16, data: [UInt8], padForStream: Bool = false) -> [UInt8] {
        var out = STUNMessage.bytes(channel) + STUNMessage.bytes(UInt16(data.count)) + data
        if padForStream {
            out += [UInt8](repeating: 0, count: (4 - data.count % 4) % 4)
        }
        return out
    }

    /// Returns (channel, payload, total framed length) or nil when incomplete.
    public static func decode(_ bytes: [UInt8], stream: Bool = false) -> (channel: UInt16, data: [UInt8], length: Int)? {
        guard looksLikeChannelData(bytes) else { return nil }
        let channel = STUNMessage.readUInt16(bytes, at: 0)
        let length = Int(STUNMessage.readUInt16(bytes, at: 2))
        let padded = stream ? (length + 3) & ~3 : length
        guard bytes.count >= 4 + padded else { return nil }
        return (channel, Array(bytes[4..<(4 + length)]), 4 + padded)
    }
}
