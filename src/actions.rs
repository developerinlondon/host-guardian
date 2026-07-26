//! Shed policy: stop a *named* unit under memory emergency.
//!
//! systemd-oomd already kills by cgroup pressure and should stay the first line
//! of defence. What it cannot express is "sacrifice this specific service to
//! keep sshd reachable" — its choice follows pressure, not an operator's
//! ranking of what is expendable.

use std::collections::HashMap;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ActionPolicy {
    pub cooldown_sec: u64,
    pub budget_window_sec: u64,
    pub max_actions_per_window: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Shed,
    SuppressedCooldown,
    SuppressedBudget,
    SuppressedObserveOnly,
}

/// Rate limiting for destructive actions, keyed by unit.
///
/// State is in memory by design. The timer-driven predecessor persisted this to
/// JSON and grew a whole corruption-recovery path; a resident daemon that is
/// restarted has, correctly, forgotten its cooldowns.
#[derive(Debug, Default)]
pub struct Budget {
    last_action: HashMap<String, u64>,
    history: Vec<u64>,
}

impl Budget {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether `unit` may be shed at `now` (unix seconds), recording the
    /// action if so. Suppressed attempts do not consume budget.
    pub fn admit(
        &mut self,
        unit: &str,
        now: u64,
        policy: &ActionPolicy,
        observe_only: bool,
    ) -> Decision {
        if let Some(&last) = self.last_action.get(unit) {
            if now.saturating_sub(last) < policy.cooldown_sec {
                return Decision::SuppressedCooldown;
            }
        }

        let cutoff = now.saturating_sub(policy.budget_window_sec);
        self.history.retain(|&t| t > cutoff);
        if self.history.len() >= policy.max_actions_per_window {
            return Decision::SuppressedBudget;
        }

        // Observe-only is checked last so a dry run exercises the same
        // cooldown and budget arithmetic the live path would.
        if observe_only {
            return Decision::SuppressedObserveOnly;
        }

        self.last_action.insert(unit.to_string(), now);
        self.history.push(now);
        Decision::Shed
    }

    #[must_use]
    pub fn actions_in_window(&self) -> usize {
        self.history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ActionPolicy {
        ActionPolicy {
            cooldown_sec: 600,
            budget_window_sec: 3600,
            max_actions_per_window: 3,
        }
    }

    #[test]
    fn first_action_is_admitted() {
        let mut b = Budget::new();
        assert_eq!(b.admit("a.service", 1000, &policy(), false), Decision::Shed);
    }

    #[test]
    fn same_unit_is_held_off_during_cooldown() {
        let mut b = Budget::new();
        b.admit("a.service", 1000, &policy(), false);
        assert_eq!(
            b.admit("a.service", 1300, &policy(), false),
            Decision::SuppressedCooldown
        );
        assert_eq!(b.admit("a.service", 1600, &policy(), false), Decision::Shed);
    }

    #[test]
    fn cooldown_is_per_unit_not_global() {
        let mut b = Budget::new();
        b.admit("a.service", 1000, &policy(), false);
        assert_eq!(b.admit("b.service", 1001, &policy(), false), Decision::Shed);
    }

    #[test]
    fn budget_caps_a_flapping_loop() {
        let mut b = Budget::new();
        for i in 0..3 {
            assert_eq!(
                b.admit(&format!("u{i}.service"), 1000 + i, &policy(), false),
                Decision::Shed
            );
        }
        assert_eq!(
            b.admit("u3.service", 1004, &policy(), false),
            Decision::SuppressedBudget
        );
    }

    #[test]
    fn budget_recovers_once_the_window_slides_past() {
        let mut b = Budget::new();
        for i in 0..3 {
            b.admit(&format!("u{i}.service"), 1000 + i, &policy(), false);
        }
        assert_eq!(
            b.admit("u9.service", 1000 + 3601, &policy(), false),
            Decision::Shed
        );
    }

    #[test]
    fn suppressed_attempts_do_not_consume_budget() {
        let mut b = Budget::new();
        b.admit("a.service", 1000, &policy(), false);
        for t in 1..50 {
            b.admit("a.service", 1000 + t, &policy(), false);
        }
        assert_eq!(b.actions_in_window(), 1, "cooldown hits burned budget");
    }

    #[test]
    fn observe_only_never_records_an_action() {
        let mut b = Budget::new();
        assert_eq!(
            b.admit("a.service", 1000, &policy(), true),
            Decision::SuppressedObserveOnly
        );
        assert_eq!(b.actions_in_window(), 0);
        // And it left no cooldown behind, so a live run right after is admitted.
        assert_eq!(b.admit("a.service", 1001, &policy(), false), Decision::Shed);
    }

    #[test]
    fn clock_going_backwards_does_not_panic_or_admit_a_flood() {
        let mut b = Budget::new();
        b.admit("a.service", 1000, &policy(), false);
        assert_eq!(
            b.admit("a.service", 5, &policy(), false),
            Decision::SuppressedCooldown
        );
    }
}
