import ConvoCore
import ConvoFoundation

/// The wake registrations a node holds (deviations: wakes): one per member
/// per group, kept in `<state>/wakes.bin` so they survive a restart, and
/// dropped when they expire.
public final class WakeRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var byGroup: [Hash32: [Hash32: WakeRegistration]] = [:]
    private let path: String?

    public init(directory: String?) {
        path = directory.map { $0 + "/wakes.bin" }
        if let path, let data = FileManager.default.contents(atPath: path) {
            var r = BorshReader(Array(data))
            if let wires = try? r.vec({ try $0.vec() }) {
                for wire in wires {
                    guard let registration = try? WakeRegistration.fromWire(wire) else { continue }
                    byGroup[registration.body.groupID, default: [:]][registration.body.memberPk] = registration
                }
            }
        }
    }

    /// Records the registration, or forgets the member's when it is a removal.
    public func register(_ registration: WakeRegistration) {
        lock.lock()
        if registration.isRemoval {
            byGroup[registration.body.groupID]?[registration.body.memberPk] = nil
        } else {
            byGroup[registration.body.groupID, default: [:]][registration.body.memberPk] = registration
        }
        lock.unlock()
        persist()
    }

    /// The live registrations for a group at `now` (unix ms).
    public func registrations(groupID: Hash32, at now: UInt64) -> [WakeRegistration] {
        lock.lock(); defer { lock.unlock() }
        return (byGroup[groupID] ?? [:]).values.filter { $0.body.expires > now }.sorted { $0.body.memberPk.hex < $1.body.memberPk.hex }
    }

    /// Drops what has expired; how many went.
    @discardableResult public func expire(now: UInt64) -> Int {
        lock.lock()
        var dropped = 0
        for (group, members) in byGroup {
            let live = members.filter { $0.value.body.expires > now }
            dropped += members.count - live.count
            byGroup[group] = live.isEmpty ? nil : live
        }
        lock.unlock()
        if dropped > 0 { persist() }
        return dropped
    }

    public var count: Int { lock.lock(); defer { lock.unlock() }; return byGroup.values.reduce(0) { $0 + $1.count } }

    private func persist() {
        guard let path else { return }
        lock.lock()
        let all = byGroup.values.flatMap { $0.values.map(\.wire) }
        lock.unlock()
        var w = BorshWriter(); w.vec(all) { w, wire in w.vec(wire) }
        try? StateFiles.write(Data(w.bytes), to: path)
    }
}
