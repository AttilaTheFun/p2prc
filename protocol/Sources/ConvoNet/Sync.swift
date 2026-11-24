import ConvoCore
import ConvoFoundation

/// §12 over a `DataChannel`: the requester sends a signed `SyncRequest`;
/// the responder streams items it holds under the wanted head that the
/// requester lacks, each independently verifiable, and ends the stream.
///
/// Frames: u8 kind ‖ payload. 0 = request (SyncRequest wire), 1 = message
/// (SignedMessage wire), 2 = attestation (borsh(Attestation) ‖ sig), 3 =
/// end (u8 status: 0 complete, 1 unknown head, 2 unauthorized).
public enum SyncFrame {
    public static let request: UInt8 = 0, message: UInt8 = 1, attestation: UInt8 = 2, end: UInt8 = 3
}

public enum SyncEnd: UInt8, Sendable { case complete = 0, unknownHead = 1, unauthorized = 2 }

public enum SyncResponder {
    /// Serves one request from `dag`: everything under `wantHead` the
    /// requester says it is missing (or everything not under its
    /// `haveHead`, when `missing` is absent), in canonical order.
    public static func serve(_ request: SyncRequest, from dag: DAG, over channel: any DataChannel) async throws {
        guard Int(request.body.requesterIdx) < dag.genesis.members.count,
              request.verify(requester: dag.genesis.members[Int(request.body.requesterIdx)]) else {
            try await channel.send([SyncFrame.end, SyncEnd.unauthorized.rawValue]); return
        }
        guard dag.contains(request.body.wantHead) else {
            try await channel.send([SyncFrame.end, SyncEnd.unknownHead.rawValue]); return
        }
        let wanted: [Hash32]
        if let missing = request.body.missing {
            wanted = missing.filter { dag.contains($0) }
        } else {
            let have = request.body.haveHead == Hash32.zero ? [] : dag.ancestors(of: request.body.haveHead)
            wanted = dag.canonicalOrder(under: request.body.wantHead).filter { !have.contains($0) }
        }
        for hash in wanted {
            try await channel.send([SyncFrame.message] + dag.messages[hash]!.wire)
        }
        for att in dag.attestations(for: request.body.wantHead) {
            try await channel.send([SyncFrame.attestation] + att.attestation.borsh + att.signature)
        }
        try await channel.send([SyncFrame.end, SyncEnd.complete.rawValue])
    }
}

public enum SyncClient {
    public struct Outcome: Sendable {
        public var inserted: [Hash32] = []
        public var rejected = 0
        public var end: SyncEnd = .complete
    }

    /// Sends the request and folds every item into `dag`, verifying each;
    /// returns once the responder ends the stream. Insertion order is the
    /// responder's canonical order, so parents arrive before children;
    /// anything still orphaned is retried after the stream.
    public static func request(_ request: SyncRequest, into dag: inout DAG, over channel: any DataChannel) async throws -> Outcome {
        try await channel.send([SyncFrame.request] + request.wire)
        var outcome = Outcome()
        var deferred: [SignedMessage] = []
        for await frame in channel.incoming {
            guard let kind = frame.first else { continue }
            let payload = Array(frame.dropFirst())
            switch kind {
            case SyncFrame.message:
                guard let signed = try? SignedMessage.fromWire(payload) else { outcome.rejected += 1; continue }
                do { outcome.inserted.append(try dag.insert(signed)) }
                catch DAG.InsertError.unknownParent { deferred.append(signed) }
                catch DAG.InsertError.duplicate { }
                catch { outcome.rejected += 1 }
            case SyncFrame.attestation:
                guard payload.count > 64, let att = try? Attestation.decode(Array(payload.dropLast(64))) else { outcome.rejected += 1; continue }
                if !dag.record(SignedAttestation(attestation: att, signature: Array(payload.suffix(64)))) { outcome.rejected += 1 }
            case SyncFrame.end:
                outcome.end = SyncEnd(rawValue: payload.first ?? 0) ?? .complete
                var progress = true
                while progress, !deferred.isEmpty {
                    progress = false
                    for (i, signed) in deferred.enumerated().reversed() {
                        if let hash = try? dag.insert(signed) { outcome.inserted.append(hash); deferred.remove(at: i); progress = true }
                    }
                }
                outcome.rejected += deferred.count
                return outcome
            default:
                continue
            }
        }
        return outcome
    }
}
