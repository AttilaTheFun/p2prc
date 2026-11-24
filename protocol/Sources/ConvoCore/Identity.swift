import Crypto
import ConvoFoundation

// §1: an identity is an Ed25519 keypair from a recovery phrase: 12 or 24
// words from the standard 2,048-word English list, its seed by PBKDF2, and
// the identity key from the seed by HKDF.

/// The recovery phrase: entropy ⇄ phrase, phrase → seed.
public enum Mnemonic {
    public enum Failure: Error, Equatable { case badWordCount, unknownWord(String), badChecksum, badEntropy }

    /// A fresh 12-word phrase (128 bits of entropy) by default; 24 words for 256.
    public static func generate(words count: Int = 12) -> [String] {
        let bits = count * 11 * 32 / 33
        var entropy = [UInt8](repeating: 0, count: bits / 8)
        for i in entropy.indices { entropy[i] = UInt8.random(in: 0...255) }
        return try! phrase(from: entropy)
    }

    public static func phrase(from entropy: [UInt8]) throws -> [String] {
        guard [16, 20, 24, 28, 32].contains(entropy.count) else { throw Failure.badEntropy }
        let checksumBits = entropy.count / 4
        let hash = Hashing.sha256(entropy).bytes
        var bits: [Bool] = []
        for byte in entropy { for i in (0..<8).reversed() { bits.append((byte >> i) & 1 == 1) } }
        for i in 0..<checksumBits { bits.append((hash[i / 8] >> (7 - i % 8)) & 1 == 1) }
        var words: [String] = []
        for w in 0..<(bits.count / 11) {
            var index = 0
            for b in bits[(w * 11)..<(w * 11 + 11)] { index = index << 1 | (b ? 1 : 0) }
            words.append(RecoveryWords.english[index])
        }
        return words
    }

    /// The entropy behind a phrase, with the checksum verified.
    public static func entropy(from words: [String]) throws -> [UInt8] {
        guard [12, 15, 18, 21, 24].contains(words.count) else { throw Failure.badWordCount }
        var bits: [Bool] = []
        for word in words {
            guard let index = RecoveryWords.index[word.lowercased()] else { throw Failure.unknownWord(word) }
            for i in (0..<11).reversed() { bits.append((index >> i) & 1 == 1) }
        }
        let entropyBits = bits.count * 32 / 33
        var entropy = [UInt8](repeating: 0, count: entropyBits / 8)
        for (i, b) in bits.prefix(entropyBits).enumerated() where b { entropy[i / 8] |= 1 << (7 - i % 8) }
        let hash = Hashing.sha256(entropy).bytes
        for (i, b) in bits.dropFirst(entropyBits).enumerated() {
            guard ((hash[i / 8] >> (7 - i % 8)) & 1 == 1) == b else { throw Failure.badChecksum }
        }
        return entropy
    }

    /// The 64-byte seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt
    /// `"mnemonic" ‖ passphrase`, over the NFKD phrase.
    public static func seed(words: [String], passphrase: String = "") -> [UInt8] {
        let phrase = normalize(words.map { $0.lowercased() }.joined(separator: " "))
        let salt = Array(normalize("mnemonic" + passphrase).utf8)
        return PBKDF2.sha512(password: Array(phrase.utf8), salt: salt, rounds: 2048, length: 64)
    }

    static func normalize(_ s: String) -> String {
        if s.unicodeScalars.allSatisfy({ $0.isASCII }) { return s }
        // NFKD needs ICU, which Isomer's Foundation on the web and Android
        // leaves out (the Android SDK's module is still importable, so
        // canImport can't tell). The English words are ASCII: only a
        // non-ASCII passphrase would differ there.
        #if os(WASI) || os(Android)
        return s
        #else
        return s.decomposedStringWithCompatibilityMapping
        #endif
    }
}

extension RecoveryWords {
    static let index: [String: Int] = {
        var m: [String: Int] = [:]
        for (i, w) in english.enumerated() { m[w] = i }
        return m
    }()
}

public enum PBKDF2 {
    public static func sha512(password: [UInt8], salt: [UInt8], rounds: Int, length: Int) -> [UInt8] {
        let key = SymmetricKey(data: password)
        var out: [UInt8] = []
        var block: UInt32 = 1
        while out.count < length {
            var u = Array(HMAC<SHA512>.authenticationCode(for: salt + withUnsafeBytes(of: block.bigEndian, Array.init), using: key))
            var t = u
            for _ in 1..<rounds {
                u = Array(HMAC<SHA512>.authenticationCode(for: u, using: key))
                for i in t.indices { t[i] ^= u[i] }
            }
            out += t
            block += 1
        }
        return Array(out.prefix(length))
    }
}

/// The reference identity derivation (§1): the identity key from a
/// recovery phrase's seed.
public enum IdentityKey {
    /// The identity's 32-byte Ed25519 seed from a recovery phrase:
    /// `HKDF-SHA256(ikm = seed, salt = "convo", info = "convo/identity/v1")`.
    public static func secret(words: [String], passphrase: String = "") -> [UInt8] {
        let seed = Mnemonic.seed(words: words, passphrase: passphrase)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: Array("convo".utf8),
            info: Array(Domain.identityInfo.utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Array($0) }
    }

    public static func key(words: [String], passphrase: String = "") throws -> SigningKey {
        try SigningKey(seed: secret(words: words, passphrase: passphrase))
    }

    /// An exported secret key: the 32-byte seed, or 64 bytes (seed ‖ public
    /// key), checked against each other.
    public static func key(secretKey bytes: [UInt8]) throws -> SigningKey {
        let key = try SigningKey(seed: Array(bytes.prefix(32)))
        if bytes.count == 64 { guard Array(bytes.suffix(32)) == key.publicKey.bytes else { throw Mnemonic.Failure.badEntropy } }
        else if bytes.count != 32 { throw Mnemonic.Failure.badEntropy }
        return key
    }
}
