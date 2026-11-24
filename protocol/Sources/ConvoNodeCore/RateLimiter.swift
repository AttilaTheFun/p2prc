import ConvoFoundation

/// Per-key token buckets — the "per-IP throttling with backoff responses"
/// of docs/architecture.md. A key (the caller's address) may spend up to
/// `burst` tokens at once and earns `perMinute` back over a minute; when it
/// is out, the caller gets a 429 with how long to wait. Buckets that have
/// refilled completely are forgotten, so memory stays bounded by the number
/// of callers active in the last minute or so.
public final class RateLimiter: @unchecked Sendable {
    public let perMinute: Double
    public let burst: Double
    private let lock = NSLock()
    private var buckets: [String: (tokens: Double, at: Double)] = [:]

    public init(perMinute: Double, burst: Double) {
        self.perMinute = perMinute
        self.burst = burst
    }

    /// Nil when allowed (a token was spent); otherwise the seconds to wait.
    public func retryAfter(_ key: String, now: Double = Date().timeIntervalSince1970) -> Int? {
        lock.lock(); defer { lock.unlock() }
        if buckets.count > 10_000 {
            // Drop whatever has fully refilled.
            buckets = buckets.filter { now - $0.value.at < 60 * burst / perMinute }
        }
        var bucket = buckets[key] ?? (burst, now)
        bucket.tokens = min(burst, bucket.tokens + (now - bucket.at) * perMinute / 60)
        bucket.at = now
        if bucket.tokens >= 1 {
            bucket.tokens -= 1
            buckets[key] = bucket
            return nil
        }
        buckets[key] = bucket
        return max(1, Int(((1 - bucket.tokens) * 60 / perMinute).rounded(.up)))
    }
}
