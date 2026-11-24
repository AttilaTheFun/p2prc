import Foundation
import Testing
@testable import ConvoNodeMain

@Test func parsesOptionsAndEnvironment() throws {
    let op = String(repeating: "ab", count: 32)
    let o = try NodeOptions.parse(["--port", "9000", "--seed", "http://a", "--no-relay", "--relay-ports", "20000-20010", "--witness", "http://w", "--operator", op],
                                  environment: ["CONVO_SEEDS": "http://b, http://c", "CONVO_STATE_DIR": "/var/convo", "CONVO_WITNESSES": "http://v"])
    #expect(o.port == 9000 && o.seeds == ["http://b", "http://c", "http://a"] && !o.relay)
    #expect(o.relayPorts == 20000...20010 && o.stateDirectory == "/var/convo")
    #expect(o.witnesses == ["http://v", "http://w"] && o.operatorPk == op)
    #expect(try NodeOptions.parse([], environment: ["PORT": "81", "CONVO_COMMIT_INTERVAL_MS": "7"]).commitIntervalMs == 7)
    #expect(throws: NodeOptions.Failure.self) { try NodeOptions.parse(["--operator", "nothex"], environment: [:]) }
    #expect(throws: NodeOptions.Failure.self) { try NodeOptions.parse(["--bogus"], environment: [:]) }
    #expect(throws: NodeOptions.Failure.self) { try NodeOptions.parse(["--relay-ports", "5-1"], environment: [:]) }
}

@Test func relayIsOnByDefault() {
    #expect(NodeOptions().relay)
    #expect(NodeOptions().turnPort == 3478)
}
