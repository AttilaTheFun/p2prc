import ConvoMLS
import Testing

/// The MLS self-test as a test: three members, commits, epochs, a
/// concurrent-commit race, and message round trips.
@Suite struct MLSTests {
    @Test func selfTestPasses() {
        for check in MLSSelfTest.run() {
            #expect(check.passed, "\(check.name): \(check.detail)")
        }
    }
}
