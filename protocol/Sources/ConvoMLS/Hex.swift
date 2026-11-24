/// Lowercase hex, without Foundation.
///
/// `String(format:)` lives in FoundationInternationalization — using it for
/// hex costs the full ICU tables in a wasm build. Radix formatting doesn't.
extension Sequence where Element == UInt8 {
    public var hexString: String {
        map { byte in
            let s = String(byte, radix: 16)
            return byte < 16 ? "0" + s : s
        }.joined()
    }
}
