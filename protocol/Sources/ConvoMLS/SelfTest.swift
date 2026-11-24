import Crypto
// FoundationEssentials has everything this file needs (Data, JSON, Date)
// without FoundationInternationalization — whose embedded ICU tables are
// ~33 MB of wasm data section. One plain `import Foundation` anywhere in the
// module graph pulls them back in.
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The MLS core exercised end to end, as a value rather than a program.
///
/// The same checks run from the command line, under wasm in Node, and inside
/// the browser UI — so "it works in the browser" means the identical
/// assertions, not a reimplementation that happens to agree.
public enum MLSSelfTest {
    public struct Check {
        public let name: String
        public let detail: String
        public let passed: Bool
    }

    private struct Person {
        let id: String
        let key: Curve25519.KeyAgreement.PrivateKey
        let group: MLSGroup
    }

    public static func run() -> [Check] {
        var checks: [Check] = []
        func check(_ name: String, _ detail: String, _ passed: Bool) {
            checks.append(Check(name: name, detail: detail, passed: passed))
        }

        check("primitives", CryptoProbe.run(), CryptoProbe.agrees)

        // At rest: a record round-trips under its identity's key, is noise
        // under another identity's, and rejects tampering.
        do {
            let identity = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
            let other = Curve25519.KeyAgreement.PrivateKey().rawRepresentation
            let plain = Data(#"[{"id":"1","text":"hello"}]"#.utf8)
            let record = try AtRest.seal(plain, key: AtRest.key(identity: identity))
            let back = try AtRest.open(record, key: AtRest.key(identity: identity))
            let wrongKey = (try? AtRest.open(record, key: AtRest.key(identity: other))) == nil
            var tampered = Array(record.utf8); tampered[tampered.count / 2] ^= 0x01
            let tamperRejected = (try? AtRest.open(String(decoding: tampered, as: UTF8.self),
                                                   key: AtRest.key(identity: identity))) == nil
            check("at-rest", "round trip \(back == plain), wrong key rejected \(wrongKey), tamper rejected \(tamperRejected)",
                  back == plain && wrongKey && tamperRejected)
        } catch {
            check("at-rest", "\(error)", false)
        }

        let people = ["alice", "bob", "carol"].map { id -> Person in
            let key = Curve25519.KeyAgreement.PrivateKey()
            return Person(id: id, key: key, group: MLSGroup(groupID: "g1", selfID: id, selfKey: key))
        }
        let roster = people.map {
            MLSGroup.Member(id: $0.id, name: $0.id, publicKey: $0.key.publicKey.rawRepresentation)
        }
        let alice = people[0]

        /// The exporter secret is the spec's designated way to compare epoch
        /// state between members without exposing key material.
        func exporters() -> [String] {
            people.map { person in
                guard let secrets = person.group.secrets else { return "none" }
                return secrets.exporterSecret.withUnsafeBytes {
                    Data($0).prefix(8).hexString
                }
            }
        }

        do {
            let commit = try alice.group.createCommit(id: "c-0001", roster: roster)
            var outcomes: [String] = []
            for person in people {
                let outcome = try person.group.apply(commit, isOwn: person.id == alice.id)
                outcomes.append("\(person.id)=\(outcome)")
            }
            let applied = people.allSatisfy { $0.group.epoch == 1 }
            check("epoch 1 commit", applied ? "all three applied" : outcomes.joined(separator: " "), applied)

            let agreed = Set(exporters()).count == 1
            check("epoch 1 secrets agree", exporters()[0], agreed)

            let sealed = try alice.group.seal("hello from alice")
            let read = try people.dropFirst().map { try $0.group.open(sealed) }
            let ok = read.allSatisfy { $0 == "hello from alice" }
            check("message round trip", ok ? "bob and carol read alice's plaintext" : "\(read)", ok)

            // Two members commit the same epoch at once, delivered in opposite
            // orders. Every member must independently land on the same winner.
            let fromBob = try people[1].group.createCommit(id: "c-0002-bob", roster: roster)
            let fromCarol = try people[2].group.createCommit(id: "c-0002-carol", roster: roster)
            var winners: [String] = []
            for person in people {
                let ordered = person.id == "bob" ? [fromCarol, fromBob] : [fromBob, fromCarol]
                var accepted = "none"
                for candidate in ordered {
                    let outcome = try person.group.apply(
                        candidate, isOwn: candidate.committer == person.id
                    )
                    if case .applied = outcome { accepted = candidate.id }
                }
                winners.append(accepted)
            }
            let converged = Set(winners).count == 1 && winners[0] == "c-0002-bob"
            check(
                "concurrent commit race",
                converged ? "all chose \(winners[0]) regardless of arrival order" : "\(winners)",
                converged
            )

            let sameEpoch = people.allSatisfy { $0.group.epoch == 2 }
            let agreed2 = sameEpoch && Set(exporters()).count == 1
            check("epoch 2 secrets agree after rollback", exporters()[0], agreed2)

            let after = try people[2].group.seal("carol after the race")
            let read2 = try [people[0], people[1]].map { try $0.group.open(after) }
            let ok2 = read2.allSatisfy { $0 == "carol after the race" }
            check("epoch 2 message round trip", ok2 ? "alice and bob read carol's plaintext" : "\(read2)", ok2)
        } catch {
            check("group protocol", "threw \(error)", false)
        }

        return checks
    }
}
