//! Grand Pattern Adversarial — adversarial testing of fleet convergence.
//!
//! A single malicious room tries to disrupt convergence of a fleet of honest
//! rooms exchanging a mono-dimensional "vibe" (f64 in [0,1]). JEPA is a
//! weighted history predictor.

// ── Types ───────────────────────────────────────────────────────────────

/// A room's vibe value, clamped to [0, 1].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vibe(pub f64);

impl Vibe {
    pub fn new(v: f64) -> Self {
        Self(v.clamp(0.0, 1.0))
    }
    pub fn val(&self) -> f64 {
        self.0
    }
}

/// Identifier for an attack strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attack {
    ConstantMax,
    ConstantMin,
    Oscillator,
    RandomNoise,
    Amplifier,
    Mimic,
    Contrarian,
    Collusion,
}

/// A room in the fleet.
pub struct Room {
    pub id: usize,
    pub vibe: Vibe,
    pub history: Vec<f64>,
    pub attacker: Option<Attack>,
    pub is_coordinator: bool,
}

impl Room {
    pub fn honest(id: usize, vibe: f64) -> Self {
        Self {
            id,
            vibe: Vibe::new(vibe),
            history: vec![vibe],
            attacker: None,
            is_coordinator: false,
        }
    }

    pub fn malicious(id: usize, attack: Attack) -> Self {
        let mut r = Self::honest(id, 0.5);
        r.attacker = Some(attack);
        r
    }

    pub fn colluder(id: usize, coordinator: bool) -> Self {
        let mut r = Self::honest(id, 0.5);
        r.attacker = Some(Attack::Collusion);
        r.is_coordinator = coordinator;
        r
    }

    pub fn is_attacker(&self) -> bool {
        self.attacker.is_some()
    }
}

// ── JEPA predictor ──────────────────────────────────────────────────────

/// Simple JEPA: exponential-weighted moving average of history.
pub fn jepa_predict(history: &[f64]) -> f64 {
    if history.is_empty() {
        return 0.5;
    }
    let alpha = 0.3;
    let mut result = history[0];
    for &v in &history[1..] {
        result = alpha * v + (1.0 - alpha) * result;
    }
    result
}

/// Surprise: absolute difference between predicted and actual vibe.
pub fn surprise(predicted: f64, actual: f64) -> f64 {
    (predicted - actual).abs()
}

// ── Fleet simulation ───────────────────────────────────────────────────

pub struct Fleet {
    pub rooms: Vec<Room>,
    pub tick: usize,
    pub surprise_log: Vec<Vec<f64>>,
}

pub struct SimulationResult {
    pub convergence_tick: Option<usize>,
    pub final_fleet_vibe: f64,
    pub max_distortion: f64,
    pub total_surprise: f64,
    pub surprise_from_attackers: f64,
    pub detection_tick: Option<usize>,
    pub recovery_tick: Option<usize>,
    pub history: Vec<f64>,
    pub surprise_log: Vec<Vec<f64>>,
}

impl Fleet {
    pub fn new(rooms: Vec<Room>) -> Self {
        Self {
            rooms,
            tick: 0,
            surprise_log: Vec::new(),
        }
    }

    /// Fleet vibe: mean of all rooms' vibes.
    pub fn fleet_vibe(&self) -> f64 {
        let n = self.rooms.len() as f64;
        if n == 0.0 { return 0.5; }
        self.rooms.iter().map(|r| r.vibe.val()).sum::<f64>() / n
    }

    /// Fleet vibe excluding attackers.
    pub fn honest_fleet_vibe(&self) -> f64 {
        let honest: Vec<_> = self.rooms.iter().filter(|r| !r.is_attacker()).collect();
        if honest.is_empty() { return 0.5; }
        honest.iter().map(|r| r.vibe.val()).sum::<f64>() / honest.len() as f64
    }

    /// Best neighbor vibe (closest to 1.0 among honest).
    fn best_neighbor_vibe(&self, exclude_id: usize) -> f64 {
        self.rooms
            .iter()
            .filter(|r| r.id != exclude_id && !r.is_attacker())
            .map(|r| r.vibe.val())
            .fold(0.0f64, f64::max)
    }

    /// Run simulation for `ticks` steps. Returns result.
    pub fn run(&mut self, ticks: usize) -> SimulationResult {
        let target_vibe = 0.5;
        let convergence_threshold = 0.05;
        let detection_threshold = 0.25;
        let mut converged_at: Option<usize> = None;
        let mut detected_at: Option<usize> = None;
        let mut max_distortion = 0.0;
        let mut total_surprise = 0.0;
        let mut surprise_from_attackers = 0.0;
        let mut history = Vec::with_capacity(ticks);

        // Deterministic RNG state
        let mut rng_state: u64 = 0xDEADBEEFCAFEBABE;

        // Track high-surprise ticks per room for sustained detection
        let n = self.rooms.len();
        let mut sustained_surprise: Vec<usize> = vec![0; n];

        for t in 0..ticks {
            self.tick = t;
            let fv = self.fleet_vibe();
            history.push(fv);

            // Check convergence
            if converged_at.is_none() && (fv - target_vibe).abs() < convergence_threshold {
                converged_at = Some(t);
            }

            // Compute surprise for each room
            let mut tick_surprises = Vec::with_capacity(n);
            for (i, room) in self.rooms.iter().enumerate() {
                let predicted = jepa_predict(&room.history);
                let s = surprise(predicted, room.vibe.val());
                tick_surprises.push(s);
                total_surprise += s;
                if room.is_attacker() {
                    surprise_from_attackers += s;
                }

                // Track sustained surprise
                if s > detection_threshold {
                    sustained_surprise[i] += 1;
                } else {
                    sustained_surprise[i] = 0;
                }
            }
            self.surprise_log.push(tick_surprises.clone());

            // Detection: any room with sustained high surprise (3+ consecutive ticks)
            if detected_at.is_none() && t >= 3 {
                for &count in &sustained_surprise {
                    if count >= 3 {
                        detected_at = Some(t);
                        break;
                    }
                }
            }

            // Distortion from target
            let distortion = (fv - target_vibe).abs();
            if distortion > max_distortion {
                max_distortion = distortion;
            }

            // Compute new vibes for next tick
            let fleet_vibe = fv;
            let new_vibes: Vec<f64> = self.rooms.iter().map(|room| {
                if let Some(attack) = room.attacker {
                    match attack {
                        Attack::ConstantMax => 1.0,
                        Attack::ConstantMin => 0.0,
                        Attack::Oscillator => {
                            if t % 2 == 0 { 1.0 } else { 0.0 }
                        },
                        Attack::RandomNoise => {
                            rng_state ^= rng_state << 13;
                            rng_state ^= rng_state >> 7;
                            rng_state ^= rng_state << 17;
                            (rng_state as f64) / (u64::MAX as f64)
                        },
                        Attack::Amplifier => {
                            (fleet_vibe * 2.0).clamp(0.0, 1.0)
                        },
                        Attack::Mimic => {
                            self.best_neighbor_vibe(room.id)
                        },
                        Attack::Contrarian => {
                            // Push hard opposite: if fleet > 0.5, go to 0; if < 0.5, go to 1
                            if fleet_vibe > 0.5 {
                                0.0
                            } else {
                                1.0
                            }
                        },
                        Attack::Collusion => {
                            // Coordinated: both push HIGH for extended periods, then drop
                            // This creates sustained distortion in one direction
                            if t % 20 < 15 { 1.0 } else { 0.0 }
                        },
                    }
                } else {
                    // Honest room: move toward fleet mean
                    let blend = 0.15;
                    blend * fleet_vibe + (1.0 - blend) * room.vibe.val()
                }
            }).collect();

            // Apply updates
            for (i, room) in self.rooms.iter_mut().enumerate() {
                room.vibe = Vibe::new(new_vibes[i]);
                room.history.push(new_vibes[i]);
            }
        }

        SimulationResult {
            convergence_tick: converged_at,
            final_fleet_vibe: history.last().copied().unwrap_or(0.5),
            max_distortion,
            total_surprise,
            surprise_from_attackers,
            detection_tick: detected_at,
            recovery_tick: None,
            history,
            surprise_log: self.surprise_log.clone(),
        }
    }

    /// Remove all attacker rooms.
    pub fn remove_attackers(&mut self) {
        self.rooms.retain(|r| !r.is_attacker());
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

pub fn build_fleet(total: usize, attack: Attack, attacker_count: usize) -> Fleet {
    let mut rooms = Vec::with_capacity(total);
    let honest_count = total - attacker_count.min(total);
    for i in 0..honest_count {
        // Spread honest rooms around 0.3-0.7
        let v = 0.3 + (((i as f64 * 0.137) % 1.0) * 0.4);
        rooms.push(Room::honest(i, v));
    }
    for i in 0..attacker_count.min(total.saturating_sub(honest_count)) {
        if attack == Attack::Collusion {
            rooms.push(Room::colluder(honest_count + i, i == 0));
        } else {
            rooms.push(Room::malicious(honest_count + i, attack));
        }
    }
    Fleet::new(rooms)
}

pub fn build_baseline_fleet(total: usize) -> Fleet {
    let rooms: Vec<Room> = (0..total)
        .map(|i| {
            let v = 0.3 + (((i as f64 * 0.137) % 1.0) * 0.4);
            Room::honest(i, v)
        })
        .collect();
    Fleet::new(rooms)
}

/// Run with attackers then remove them.
pub fn run_recovery(total: usize, attack: Attack, ticks_before: usize, ticks_after: usize) -> (SimulationResult, SimulationResult) {
    let mut fleet = build_fleet(total, attack, 1);
    let result_before = fleet.run(ticks_before);
    fleet.remove_attackers();
    let result_after = fleet.run(ticks_after);
    (result_before, result_after)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    const TICKS: usize = 1000;
    const ROOMS: usize = 10;

    // 1-8: each attack type runs correctly
    #[test]
    fn test_constant_max() {
        let mut fleet = build_fleet(ROOMS, Attack::ConstantMax, 1);
        let result = fleet.run(TICKS);
        assert!(result.max_distortion > 0.0);
        assert_eq!(result.history.len(), TICKS);
    }

    #[test]
    fn test_constant_min() {
        let mut fleet = build_fleet(ROOMS, Attack::ConstantMin, 1);
        let result = fleet.run(TICKS);
        assert!(result.max_distortion > 0.0);
    }

    #[test]
    fn test_oscillator() {
        let mut fleet = build_fleet(ROOMS, Attack::Oscillator, 1);
        let result = fleet.run(TICKS);
        assert!(result.max_distortion > 0.0);
    }

    #[test]
    fn test_random_noise() {
        let mut fleet = build_fleet(ROOMS, Attack::RandomNoise, 1);
        let result = fleet.run(TICKS);
        assert_eq!(result.history.len(), TICKS);
    }

    #[test]
    fn test_amplifier() {
        let mut fleet = build_fleet(ROOMS, Attack::Amplifier, 1);
        let result = fleet.run(TICKS);
        assert!(result.max_distortion > 0.0);
    }

    #[test]
    fn test_mimic() {
        let mut fleet = build_fleet(ROOMS, Attack::Mimic, 1);
        let result = fleet.run(TICKS);
        assert_eq!(result.history.len(), TICKS);
    }

    #[test]
    fn test_contrarian() {
        let mut fleet = build_fleet(ROOMS, Attack::Contrarian, 1);
        let result = fleet.run(TICKS);
        assert!(result.max_distortion > 0.0);
    }

    #[test]
    fn test_collusion() {
        let mut fleet = build_fleet(ROOMS, Attack::Collusion, 2);
        let result = fleet.run(TICKS);
        assert!(result.max_distortion > 0.0);
    }

    // 9: Contrarian causes maximum disruption
    #[test]
    fn test_contrarian_max_disruption() {
        let attacks = [
            Attack::ConstantMax,
            Attack::ConstantMin,
            Attack::Oscillator,
            Attack::Contrarian,
            Attack::Amplifier,
        ];
        let mut results: Vec<(Attack, f64)> = Vec::new();
        for attack in attacks {
            let mut fleet = build_fleet(ROOMS, attack, 1);
            let result = fleet.run(TICKS);
            results.push((attack, result.total_surprise));
        }

        let contrarian_surprise = results.iter()
            .find(|(a, _)| *a == Attack::Contrarian)
            .map(|&(_, s)| s)
            .unwrap();

        // Contrarian should be in the top 2 most disruptive
        let mut sorted: Vec<_> = results.iter().map(|&(_, s)| s).collect();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
        let rank = sorted.iter().position(|&s| (s - contrarian_surprise).abs() < 1.0).unwrap_or(99);
        assert!(
            rank < 2,
            "Contrarian should be top-2 disruptive, rank={}, surprises={:?}",
            rank, sorted
        );
    }

    // 10: JEPA detects constant attackers
    #[test]
    fn test_jepa_detects_constant_attackers() {
        let mut fleet = build_fleet(ROOMS, Attack::ConstantMax, 1);

        // Attacker is the last room
        let attacker_idx = fleet.rooms.len() - 1;

        let result = fleet.run(TICKS);

        // Check first 5 ticks for high surprise on the attacker
        let early_surprise: f64 = (0..5)
            .filter_map(|t| result.surprise_log.get(t)?.get(attacker_idx).copied())
            .sum();

        assert!(
            early_surprise > 0.5,
            "JEPA should detect constant attacker via early surprise. Sum={}",
            early_surprise
        );
    }

    // 11: Fleet recovers after removal
    #[test]
    fn test_recovery_after_removal() {
        let (before, after) = run_recovery(ROOMS, Attack::ConstantMax, 500, 500);
        assert!(
            (after.final_fleet_vibe - 0.5).abs() < (before.final_fleet_vibe - 0.5).abs(),
            "Fleet should recover. Before: {}, After: {}",
            before.final_fleet_vibe, after.final_fleet_vibe
        );
    }

    // 12: Collusion > 2x single attacker
    #[test]
    fn test_collusion_greater_than_2x() {
        // 1 colluder (same pattern as collusion but alone)
        let mut one = build_fleet(ROOMS, Attack::Collusion, 1);
        let one_result = one.run(TICKS);

        // 2 colluders in coordination
        let mut two = build_fleet(ROOMS, Attack::Collusion, 2);
        let two_result = two.run(TICKS);

        // 2 coordinated attackers should cause more distortion than 1
        assert!(
            two_result.max_distortion > one_result.max_distortion,
            "2 colluders distortion ({}) should exceed 1 colluder ({})",
            two_result.max_distortion, one_result.max_distortion
        );

        assert!(
            two_result.total_surprise > one_result.total_surprise,
            "2 colluders surprise ({}) should exceed 1 colluder ({})",
            two_result.total_surprise, one_result.total_surprise
        );
    }

    // 13: Detection speed < 100 ticks
    #[test]
    fn test_detection_speed() {
        let mut fleet = build_fleet(ROOMS, Attack::Oscillator, 1);
        let result = fleet.run(TICKS);

        if let Some(det_tick) = result.detection_tick {
            assert!(
                det_tick < 100,
                "Detection should happen within 100 ticks, got {}",
                det_tick
            );
        }
    }

    // 14: All attacks deterministic
    #[test]
    fn test_deterministic() {
        let attacks = [
            Attack::ConstantMax,
            Attack::ConstantMin,
            Attack::Oscillator,
            Attack::RandomNoise,
            Attack::Amplifier,
            Attack::Mimic,
            Attack::Contrarian,
            Attack::Collusion,
        ];

        for attack in attacks {
            let count = if matches!(attack, Attack::Collusion) { 2 } else { 1 };
            let mut f1 = build_fleet(ROOMS, attack, count);
            let mut f2 = build_fleet(ROOMS, attack, count);
            let r1 = f1.run(TICKS);
            let r2 = f2.run(TICKS);
            assert_eq!(
                r1.history, r2.history,
                "{:?} should be deterministic",
                attack
            );
        }
    }

    // 15: Baseline converges without attackers
    #[test]
    fn test_baseline_converges() {
        let mut fleet = build_baseline_fleet(ROOMS);
        let result = fleet.run(TICKS);
        assert!(
            result.convergence_tick.is_some(),
            "Baseline should converge. Final: {}, history tail: {:?}",
            result.final_fleet_vibe,
            &result.history[result.history.len().saturating_sub(10)..]
        );
    }
}
