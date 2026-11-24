import ConvoCore
import ConvoFoundation

/// Part III §22: offer, answer and ICE candidates between two members,
/// through a node's rendezvous boxes. Plain fields, so every platform's
/// WebRTC stack maps them; `ConvoWebRTC` does it for Communication.
public enum SignalingFrame: Sendable, Equatable {
    case offer(sdp: String)
    case answer(sdp: String)
    case candidate(sdp: String, sdpMLineIndex: Int32, sdpMid: String?)

    public var wire: [UInt8] {
        var w = BorshWriter()
        switch self {
        case .offer(let sdp): w.u8(0); w.string(sdp)
        case .answer(let sdp): w.u8(1); w.string(sdp)
        case .candidate(let sdp, let index, let mid): w.u8(2); w.string(sdp); w.u32(UInt32(bitPattern: index)); w.option(mid) { w, m in w.string(m) }
        }
        return w.bytes
    }

    public static func fromWire(_ bytes: [UInt8]) throws -> SignalingFrame {
        var r = BorshReader(bytes)
        switch try r.u8() {
        case 0: return .offer(sdp: try r.string())
        case 1: return .answer(sdp: try r.string())
        case 2:
            let sdp = try r.string(), index = Int32(bitPattern: try r.u32()), mid = try r.option { try $0.string() }
            return .candidate(sdp: sdp, sdpMLineIndex: index, sdpMid: mid)
        default: throw BorshError("unknown signaling frame")
        }
    }
}
