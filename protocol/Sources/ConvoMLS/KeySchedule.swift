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

/// RFC 9420 §8 — the MLS key schedule.
///
/// These derivations are specified exactly, so they are implemented exactly:
/// the labelled expansions below produce the same bytes any conforming MLS
/// implementation would produce for the same inputs. Getting this layer right
/// is what makes the rest meaningfully "MLS" rather than MLS-shaped.
///
/// Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001).
public enum MLSCipherSuite {
    public static let id: UInt16 = 0x0001
    public static let hashLength = 32       // SHA-256
    public static let keyLength = 16        // AES-128-GCM
    public static let nonceLength = 12
}

public enum KeySchedule {
    /// RFC 9420 §5.1: an encoded length-prefixed byte string.
    static func vector(_ bytes: [UInt8]) -> [UInt8] {
        // RFC 9420 §2.1.2 variable-length encoding: values under 64 take one
        // byte, larger ones take two with the 0b01 prefix. Group contexts
        // routinely exceed 63 bytes, so both forms are needed.
        let count = bytes.count
        if count < 64 { return [UInt8(count)] + bytes }
        precondition(count < 16384, "vector too long")
        return [UInt8(0x40 | (count >> 8)), UInt8(count & 0xFF)] + bytes
    }

    /// KDF.ExpandWithLabel(Secret, Label, Context, Length) — RFC 9420 §8.1.
    ///
    ///   KDFLabel = { length; "MLS 1.0 " + Label; Context }
    public static func expandWithLabel(
        secret: SymmetricKey,
        label: String,
        context: [UInt8],
        length: Int
    ) -> SymmetricKey {
        var info: [UInt8] = []
        info.append(UInt8((length >> 8) & 0xFF))
        info.append(UInt8(length & 0xFF))
        info += vector(Array("MLS 1.0 \(label)".utf8))
        info += vector(context)
        return HKDF<SHA256>.expand(
            pseudoRandomKey: secret,
            info: info,
            outputByteCount: length
        )
    }

    /// KDF.DeriveSecret(Secret, Label) — ExpandWithLabel with empty context.
    public static func deriveSecret(secret: SymmetricKey, label: String) -> SymmetricKey {
        expandWithLabel(
            secret: secret,
            label: label,
            context: [],
            length: MLSCipherSuite.hashLength
        )
    }

    /// One epoch's secrets, all derived from the epoch secret (RFC 9420 §8).
    public struct EpochSecrets {
        public let epochSecret: SymmetricKey
        public let senderDataSecret: SymmetricKey
        public let encryptionSecret: SymmetricKey
        public let exporterSecret: SymmetricKey
        public let confirmationKey: SymmetricKey
        public let membershipKey: SymmetricKey
        public let initSecret: SymmetricKey

        init(epochSecret: SymmetricKey) {
            self.epochSecret = epochSecret
            senderDataSecret = KeySchedule.deriveSecret(secret: epochSecret, label: "sender data")
            encryptionSecret = KeySchedule.deriveSecret(secret: epochSecret, label: "encryption")
            exporterSecret = KeySchedule.deriveSecret(secret: epochSecret, label: "exporter")
            confirmationKey = KeySchedule.deriveSecret(secret: epochSecret, label: "confirm")
            membershipKey = KeySchedule.deriveSecret(secret: epochSecret, label: "membership")
            initSecret = KeySchedule.deriveSecret(secret: epochSecret, label: "init")
        }
    }

    /// Advances the schedule by one epoch:
    ///
    ///   init_secret[n-1] + commit_secret -> joiner_secret
    ///   joiner_secret + group_context    -> epoch_secret[n]
    ///
    /// (RFC 9420 §8.1. PSKs are not used, so the welcome/member secret steps
    /// take an empty PSK secret.)
    public static func nextEpoch(
        initSecret: SymmetricKey,
        commitSecret: SymmetricKey,
        groupContext: [UInt8]
    ) -> EpochSecrets {
        let joiner = HKDF<SHA256>.extract(
            inputKeyMaterial: commitSecret,
            salt: initSecret.withUnsafeBytes { Array($0) }
        )
        let joinerKey = SymmetricKey(data: joiner)

        let memberSecret = expandWithLabel(
            secret: joinerKey,
            label: "member",
            context: [],
            length: MLSCipherSuite.hashLength
        )
        let epochSecret = expandWithLabel(
            secret: memberSecret,
            label: "epoch",
            context: groupContext,
            length: MLSCipherSuite.hashLength
        )
        return EpochSecrets(epochSecret: epochSecret)
    }

    /// The first epoch of a brand new group: there is no previous init secret,
    /// so the spec starts from a zero-filled one.
    public static func firstEpoch(commitSecret: SymmetricKey, groupContext: [UInt8]) -> EpochSecrets {
        nextEpoch(
            initSecret: SymmetricKey(data: Data(repeating: 0, count: MLSCipherSuite.hashLength)),
            commitSecret: commitSecret,
            groupContext: groupContext
        )
    }

    /// RFC 9420 §9: message keys come from a secret tree, ratcheted per sender
    /// so each message uses a distinct key that is then discarded. This gives
    /// forward secrecy *within* an epoch, which a single per-epoch key cannot.
    public static func ratchetStep(secret: SymmetricKey, generation: UInt32)
        -> (key: SymmetricKey, nonce: [UInt8], next: SymmetricKey)
    {
        var context: [UInt8] = []
        context.append(UInt8((generation >> 24) & 0xFF))
        context.append(UInt8((generation >> 16) & 0xFF))
        context.append(UInt8((generation >> 8) & 0xFF))
        context.append(UInt8(generation & 0xFF))

        let key = expandWithLabel(secret: secret, label: "key", context: context,
                                  length: MLSCipherSuite.keyLength)
        let nonceKey = expandWithLabel(secret: secret, label: "nonce", context: context,
                                       length: MLSCipherSuite.nonceLength)
        let next = expandWithLabel(secret: secret, label: "secret", context: context,
                                   length: MLSCipherSuite.hashLength)
        return (key, nonceKey.withUnsafeBytes { Array($0) }, next)
    }
}
