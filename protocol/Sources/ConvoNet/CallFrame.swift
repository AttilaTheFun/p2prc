import ConvoCore
import ConvoFoundation

/// Part III §25: a call between two members on the connection that already
/// carries their data channel. Three frames on that channel, tags 4–6 of
/// the data-channel framing (§23); the media is renegotiated onto the same
/// peer connection, so the call and the chat share ICE and DTLS.
public enum CallFrame: Sendable, Equatable {
    public static let offerTag: UInt8 = 4, answerTag: UInt8 = 5, endTag: UInt8 = 6

    /// The caller's renegotiation offer. `video` says whether the caller
    /// sends a camera and wants one back.
    case offer(sdp: String, video: Bool)
    /// The callee's renegotiation answer.
    case answer(sdp: String)
    /// Either side: the call is over; media lines go inactive on the next
    /// negotiation, the data channel stays.
    case end

    public var wire: [UInt8] {
        var w = BorshWriter()
        switch self {
        case .offer(let sdp, let video): w.u8(Self.offerTag); w.u8(video ? 1 : 0); w.string(sdp)
        case .answer(let sdp): w.u8(Self.answerTag); w.string(sdp)
        case .end: w.u8(Self.endTag)
        }
        return w.bytes
    }

    /// Nil for a frame that is not a call frame (the sync tags, §23).
    public static func fromWire(_ bytes: [UInt8]) throws -> CallFrame? {
        var r = BorshReader(bytes)
        switch try r.u8() {
        case offerTag:
            let video = try r.u8() != 0
            let sdp = try r.string()
            try r.finish()
            return .offer(sdp: sdp, video: video)
        case answerTag:
            let sdp = try r.string()
            try r.finish()
            return .answer(sdp: sdp)
        case endTag:
            try r.finish()
            return .end
        default:
            return nil
        }
    }
}
