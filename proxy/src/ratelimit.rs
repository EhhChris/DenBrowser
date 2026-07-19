//! Per-origin-IP request rate limiting for the DenBrowser proxy.
//!
//! Two layers, both keyed by the client IP and both configured in the proxy
//! config file (see [`crate::config`]):
//!
//! * a **universal cap** — at most N requests per window from any single IP,
//!   across every request; and
//! * optional **per-URL-pattern rules** — a glob matched against `host + path`,
//!   each with its own window and cap and its *own* counter, so a flood against
//!   `example.com/secrets/*` is throttled independently of `example.com/news/*`
//!   and of the universal budget.
//!
//! Counting is delegated to [`pingora_limits::rate::Rate`], a lock-free sliding
//! estimator: `observe(&key, 1)` records the request and returns the estimated
//! count in the current window, which we compare against the configured cap.
//! Because each [`Rate`] instance is a distinct estimator keyed only by IP,
//! "tracked independently per origin IP" falls out naturally — one estimator per
//! rule (plus one for the universal cap), each sharded by client IP inside.

use std::net::IpAddr;
use std::time::Duration;

use globset::{Glob, GlobMatcher};
use pingora_limits::rate::Rate;

use crate::config::RateLimitConfig;

/// A single counting layer: a sliding-window estimator plus its cap.
struct Limit {
    rate: Rate,
    max: isize,
}

impl Limit {
    fn new(window_secs: u64, max: isize) -> Self {
        Self {
            rate: Rate::new(Duration::from_secs(window_secs)),
            max,
        }
    }

    /// Record one request from `ip` and report whether it stays within the cap.
    /// `observe` returns the running count in the current window; a request is
    /// allowed as long as that count does not *exceed* `max`, so `max = N`
    /// permits exactly N requests per window before the (N+1)th is rejected.
    fn admit(&self, ip: &IpAddr) -> bool {
        self.rate.observe(ip, 1) <= self.max
    }
}

/// A per-URL-pattern rule: its glob and the limit it enforces.
struct Rule {
    matcher: GlobMatcher,
    limit: Limit,
}

/// The assembled rate limiter.  Built once at startup from config and shared
/// (immutably) across all worker threads — the interior counters are
/// thread-safe.
pub struct RateLimiter {
    universal: Option<Limit>,
    rules: Vec<Rule>,
}

impl RateLimiter {
    /// Build a limiter from config, or `None` when rate limiting is disabled.
    ///
    /// Returns an error on an unusable configuration (a rule with a zero window,
    /// a non-positive cap, or a glob that fails to compile) so misconfiguration
    /// surfaces loudly at startup rather than silently letting traffic through.
    pub fn from_config(cfg: &RateLimitConfig) -> anyhow::Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }

        let universal = if cfg.window_secs > 0 && cfg.max_requests > 0 {
            Some(Limit::new(cfg.window_secs, cfg.max_requests))
        } else {
            None
        };

        let mut rules = Vec::with_capacity(cfg.rules.len());
        for r in &cfg.rules {
            if r.window_secs == 0 {
                anyhow::bail!("rate-limit rule {:?} has window_secs = 0", r.pattern);
            }
            if r.max_requests <= 0 {
                anyhow::bail!(
                    "rate-limit rule {:?} has max_requests = {} (must be > 0)",
                    r.pattern,
                    r.max_requests
                );
            }
            let matcher = Glob::new(&r.pattern)
                .map_err(|e| anyhow::anyhow!("invalid rate-limit pattern {:?}: {e}", r.pattern))?
                .compile_matcher();
            rules.push(Rule {
                matcher,
                limit: Limit::new(r.window_secs, r.max_requests),
            });
        }

        if universal.is_none() && rules.is_empty() {
            anyhow::bail!(
                "rate_limiting is enabled but no universal cap (window_secs/max_requests) \
                 and no rules are configured"
            );
        }

        Ok(Some(Self { universal, rules }))
    }

    /// Decide whether a request from `ip` targeting `target` (`"{host}{path}"`)
    /// is admitted.  Returns `true` to allow, `false` to reject (429).
    ///
    /// The universal cap is charged first; then the first matching per-pattern
    /// rule (rules are evaluated in file order, first match wins).  Both layers
    /// that apply record the request, so a request counts against the universal
    /// budget *and* its pattern's budget.
    pub fn admit(&self, ip: &IpAddr, target: &str) -> bool {
        if let Some(u) = &self.universal
            && !u.admit(ip)
        {
            return false;
        }
        for rule in &self.rules {
            if rule.matcher.is_match(target) {
                return rule.limit.admit(ip);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleConfig;

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    fn other_ip() -> IpAddr {
        "203.0.113.8".parse().unwrap()
    }

    #[test]
    fn disabled_config_builds_no_limiter() {
        let cfg = RateLimitConfig::default();
        assert!(RateLimiter::from_config(&cfg).unwrap().is_none());
    }

    #[test]
    fn enabled_but_empty_is_an_error() {
        let cfg = RateLimitConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(RateLimiter::from_config(&cfg).is_err());
    }

    #[test]
    fn bad_rule_is_rejected() {
        let cfg = RateLimitConfig {
            enabled: true,
            rules: vec![RuleConfig {
                pattern: "x/*".into(),
                window_secs: 0,
                max_requests: 5,
            }],
            ..Default::default()
        };
        assert!(RateLimiter::from_config(&cfg).is_err());
    }

    #[test]
    fn universal_cap_admits_exactly_max_then_rejects() {
        let cfg = RateLimitConfig {
            enabled: true,
            // Long window so the whole test runs inside one interval.
            window_secs: 3600,
            max_requests: 3,
            rules: vec![],
        };
        let rl = RateLimiter::from_config(&cfg).unwrap().unwrap();
        assert!(rl.admit(&ip(), "example.com/"));
        assert!(rl.admit(&ip(), "example.com/"));
        assert!(rl.admit(&ip(), "example.com/"));
        assert!(!rl.admit(&ip(), "example.com/"));
    }

    #[test]
    fn different_ips_have_independent_budgets() {
        let cfg = RateLimitConfig {
            enabled: true,
            window_secs: 3600,
            max_requests: 1,
            rules: vec![],
        };
        let rl = RateLimiter::from_config(&cfg).unwrap().unwrap();
        assert!(rl.admit(&ip(), "example.com/"));
        assert!(!rl.admit(&ip(), "example.com/"));
        // A different origin IP is unaffected by the first IP's exhaustion.
        assert!(rl.admit(&other_ip(), "example.com/"));
    }

    #[test]
    fn pattern_rule_is_tracked_independently_of_other_patterns() {
        let cfg = RateLimitConfig {
            enabled: true,
            // No universal cap; only per-pattern rules.
            window_secs: 0,
            max_requests: 0,
            rules: vec![
                RuleConfig {
                    pattern: "example.com/secrets/*".into(),
                    window_secs: 3600,
                    max_requests: 1,
                },
                RuleConfig {
                    pattern: "example.com/news/*".into(),
                    window_secs: 3600,
                    max_requests: 5,
                },
            ],
        };
        let rl = RateLimiter::from_config(&cfg).unwrap().unwrap();

        // Exhaust the strict /secrets/ budget.
        assert!(rl.admit(&ip(), "example.com/secrets/a"));
        assert!(!rl.admit(&ip(), "example.com/secrets/b"));
        // /news/ has its own budget for the same IP — untouched.
        assert!(rl.admit(&ip(), "example.com/news/a"));
        assert!(rl.admit(&ip(), "example.com/news/b"));
        // Unmatched paths have no rule and no universal cap: always allowed.
        assert!(rl.admit(&ip(), "example.com/other"));
        assert!(rl.admit(&ip(), "example.com/other"));
    }

    #[test]
    fn universal_and_pattern_caps_compose() {
        let cfg = RateLimitConfig {
            enabled: true,
            window_secs: 3600,
            max_requests: 10,
            rules: vec![RuleConfig {
                pattern: "example.com/secrets/*".into(),
                window_secs: 3600,
                max_requests: 2,
            }],
        };
        let rl = RateLimiter::from_config(&cfg).unwrap().unwrap();
        // The tight per-pattern cap bites well before the universal one.
        assert!(rl.admit(&ip(), "example.com/secrets/a"));
        assert!(rl.admit(&ip(), "example.com/secrets/b"));
        assert!(!rl.admit(&ip(), "example.com/secrets/c"));
    }
}
