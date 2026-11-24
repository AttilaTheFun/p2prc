import ConvoNet
import Testing

@Test func callFramesRoundTrip() throws {
    for frame in [CallFrame.offer(sdp: "v=0\r\nm=audio", video: true), .offer(sdp: "x", video: false), .answer(sdp: "v=0"), .end] {
        #expect(try CallFrame.fromWire(frame.wire) == frame)
    }
    #expect(try CallFrame.fromWire([SyncFrame.request, 1, 2]) == nil)
    #expect(CallFrame.end.wire == [6])
    #expect(CallFrame.offer(sdp: "a", video: true).wire == [4, 1, 1, 0, 0, 0, 0x61])
}
