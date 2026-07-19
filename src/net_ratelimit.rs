//! Tier 1 — loose, network-level rate limiting (anti-DoS only, HA-first).
//!
//! A per-client token bucket with a deliberately generous ceiling: normal use
//! is never throttled; the limiter only sheds load when a single identity
//! floods the API, so one abusive client can't degrade availability for the
//! rest. Keyed by the mTLS client-cert CN (every request is authenticated),
//! falling back to the peer IP. Shared across all worker threads.
//!
//! Defaults (override via env): 100 req/s sustained, 200 burst, per client.
//!   BLACKBOOK_NET_RATE_PER_SEC, BLACKBOOK_NET_BURST  (0 disables the limiter)

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct NetRateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: f64,       // burst size
    refill_per_sec: f64, // sustained rate
    enabled: bool,
}

impl NetRateLimiter {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
            enabled: capacity > 0.0 && refill_per_sec > 0.0,
        }
    }

    /// Build from env with generous high-availability defaults.
    pub fn from_env() -> Self {
        let refill = std::env::var("BLACKBOOK_NET_RATE_PER_SEC").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(100.0);
        let burst = std::env::var("BLACKBOOK_NET_BURST").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(200.0);
        let me = Self::new(burst, refill);
        if me.enabled {
            log::info!("network rate limit: {refill}/s sustained, {burst} burst, per client");
        } else {
            log::warn!("network rate limit DISABLED (BLACKBOOK_NET_RATE_PER_SEC/BURST = 0)");
        }
        me
    }

    /// Consume one token for `key`. `true` = allowed. Disabled limiter always
    /// allows. Refills lazily based on elapsed time since the last request.
    pub fn allow(&self, key: &str) -> bool {
        if !self.enabled { return true; }
        let now = Instant::now();
        let mut buckets = self.buckets.lock();
        // Bound memory: sweep idle buckets if the map gets large.
        if buckets.len() > 8192 {
            buckets.retain(|_, b| now.duration_since(b.last).as_secs() < 300);
        }
        let b = buckets.entry(key.to_string())
            .or_insert(Bucket { tokens: self.capacity, last: now });
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_throttles_then_refills() {
        // capacity 3, refill 1000/s so refill is fast for the test.
        let rl = NetRateLimiter::new(3.0, 1000.0);
        // Burst of 3 allowed immediately.
        assert!(rl.allow("a"));
        assert!(rl.allow("a"));
        assert!(rl.allow("a"));
        // 4th in the same instant is throttled (no time to refill).
        assert!(!rl.allow("a"));
        // A different client has its own bucket.
        assert!(rl.allow("b"));
        // After a refill window, "a" recovers.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(rl.allow("a"));
    }

    #[test]
    fn disabled_limiter_always_allows() {
        let rl = NetRateLimiter::new(0.0, 0.0);
        for _ in 0..1000 { assert!(rl.allow("x")); }
    }
}
