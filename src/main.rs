//! Grand Pattern Adversarial Testing
//!
//! Can a single malicious room disrupt fleet convergence?
//! 8 attack types, 5 metrics, 15+ tests. Pure Rust, zero dependencies.

use std::fmt;

// ─── Constants ───────────────────────────────────────────────────────────────

const ROOM_COUNT: usize = 10;
const DEFAULT_TICKS: usize = 1000;
const ATTACKER_RATIO: f64 = 0.1; // 10%
const CONVERGENCE_THRESHOLD: f64 = 0.02;
const JEPA_ANOMALY_SIGMA: f64 = 2.0; // flag if > 2σ from fleet mean
const LEARNING_RATE: f64 = 0.1;
const INFLUENCE_DECAY: f64 = 0.95;

// ─── Attack Types ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttackType {
    Honest,       // normal behavior
    ConstantMax,  // always reports 1.0
    ConstantMin,  // always reports 0.0
    Oscillator,   // alternates 1.0/0.0
    RandomNoise,  // deterministic PRNG-based noise
    Amplifier,    // reports 2x fleet vibe (clamped)
    Mimic,        // copies most influential neighbor
    Contrarian,   // reports inverse of fleet vibe
    Collusion,    // coordinated oscillation (pair)
}

impl AttackType {
    pub fn name(&self) -> &'static str {
        match self {
            AttackType::Honest => "honest",
            AttackType::ConstantMax => "constant_max",
            AttackType::ConstantMin => "constant_min",
            AttackType::Oscillator => "oscillator",
            AttackType::RandomNoise => "random_noise",
            AttackType::Amplifier => "amplifier",
            AttackType::Mimic => "mimic",
            AttackType::Contrarian => "contrarian",
            AttackType::Collusion => "collusion",
        }
    }

    /// All attack types (excluding Honest)
    pub fn all_attacks() -> &'static [AttackType] {
        &[
            AttackType::ConstantMax,
            AttackType::ConstantMin,
            AttackType::Oscillator,
            AttackType::RandomNoise,
            AttackType::Amplifier,
            AttackType::Mimic,
            AttackType::Contrarian,
            AttackType::Collusion,
        ]
    }
}

// ─── Room ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Room {
    pub id: usize,
    pub vibe: f64,
    pub attack: AttackType,
    pub oscillator_state: bool,
    pub prng_state: u64, // for deterministic random noise
    pub surprise: f64,
    pub reported_vibe: f64,
    pub flagged_anomalous: bool,
    pub anomaly_tick: Option<usize>, // when first flagged
    pub influence_weight: f64,
}

impl Room {
    pub fn new(id: usize, attack: AttackType) -> Self {
        // Deterministic initial vibe spread across [0.3, 0.7]
        let base = 0.3 + (id as f64 / ROOM_COUNT as f64) * 0.4;
        Self {
            id,
            vibe: base,
            attack,
            oscillator_state: false,
            prng_state: (id as u64).wrapping_mul(6364136223846793005).wrapping_add(1),
            surprise: 0.0,
            reported_vibe: base,
            flagged_anomalous: false,
            anomaly_tick: None,
            influence_weight: 1.0 / ROOM_COUNT as f64,
        }
    }

    /// Simple xorshift64 PRNG — deterministic, no deps
    fn next_random(&mut self) -> f64 {
        self.prng_state ^= self.prng_state << 13;
        self.prng_state ^= self.prng_state >> 7;
        self.prng_state ^= self.prng_state << 17;
        (self.prng_state as f64 / u64::MAX as f64).clamp(0.0, 1.0)
    }

    /// Compute what this room reports given fleet vibe
    pub fn report(&mut self, fleet_vibe: f64, neighbors: &[(usize, f64)]) -> f64 {
        let reported = match self.attack {
            AttackType::Honest => self.vibe,
            AttackType::ConstantMax => 1.0,
            AttackType::ConstantMin => 0.0,
            AttackType::Oscillator => {
                self.oscillator_state = !self.oscillator_state;
                if self.oscillator_state { 1.0 } else { 0.0 }
            }
            AttackType::RandomNoise => self.next_random(),
            AttackType::Amplifier => (fleet_vibe * 2.0).clamp(0.0, 1.0),
            AttackType::Mimic => {
                // Copy the most influential neighbor's vibe
                if let Some((_, nv)) = neighbors.iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)) {
                    *nv
                } else {
                    self.vibe
                }
            }
            AttackType::Contrarian => 1.0 - fleet_vibe,
            AttackType::Collusion => {
                self.oscillator_state = !self.oscillator_state;
                if self.oscillator_state { 1.0 } else { 0.0 }
            }
        };
        self.reported_vibe = reported;
        reported
    }

    /// Update internal vibe toward reported (for honest rooms) or stay fixed
    pub fn update_vibe(&mut self, fleet_vibe: f64) {
        if self.attack == AttackType::Honest {
            // Move toward fleet average
            self.vibe += LEARNING_RATE * (fleet_vibe - self.vibe);
            self.vibe = self.vibe.clamp(0.0, 1.0);
        }
        // Attackers keep their strategy-driven reporting
    }
}

// ─── Simulation ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Simulation {
    pub rooms: Vec<Room>,
    pub tick: usize,
    pub max_ticks: usize,
    pub fleet_vibe_history: Vec<f64>,
    pub surprise_history: Vec<f64>,
    pub converged_tick: Option<usize>,
    pub attacker_count: usize,
}

impl Simulation {
    pub fn new(max_ticks: usize, attacker_profiles: &[(usize, AttackType)]) -> Self {
        let attacker_ids: Vec<usize> = attacker_profiles.iter().map(|(id, _)| *id).collect();
        let rooms: Vec<Room> = (0..ROOM_COUNT)
            .map(|id| {
                let attack = attacker_profiles.iter()
                    .find(|(aid, _)| *aid == id)
                    .map(|(_, at)| *at)
                    .unwrap_or(AttackType::Honest);
                Room::new(id, attack)
            })
            .collect();
        let attacker_count = attacker_ids.len();
        Self {
            rooms,
            tick: 0,
            max_ticks,
            fleet_vibe_history: Vec::with_capacity(max_ticks),
            surprise_history: Vec::with_capacity(max_ticks),
            converged_tick: None,
            attacker_count,
        }
    }

    /// Fleet vibe = weighted average of reported vibes
    pub fn fleet_vibe(&self) -> f64 {
        let total_weight: f64 = self.rooms.iter().map(|r| r.influence_weight).sum();
        let weighted: f64 = self.rooms.iter()
            .map(|r| r.reported_vibe * r.influence_weight)
            .sum();
        if total_weight > 0.0 { weighted / total_weight } else { 0.5 }
    }

    /// Fleet surprise = mean of individual room surprises
    pub fn fleet_surprise(&self) -> f64 {
        self.rooms.iter().map(|r| r.surprise).sum::<f64>() / self.rooms.len() as f64
    }

    /// JEPA anomaly detection: flag rooms whose reported vibe is > Nσ from fleet mean
    pub fn jepa_detect(&mut self) {
        let fleet = self.fleet_vibe();
        let n = self.rooms.len() as f64;
        let mean = fleet;
        let variance: f64 = self.rooms.iter()
            .map(|r| (r.reported_vibe - mean).powi(2))
            .sum::<f64>() / n;
        let stddev = variance.sqrt().max(1e-10);

        for room in &mut self.rooms {
            let z_score = (room.reported_vibe - mean) / stddev;
            if z_score.abs() > JEPA_ANOMALY_SIGMA && !room.flagged_anomalous {
                room.flagged_anomalous = true;
                if room.anomaly_tick.is_none() {
                    room.anomaly_tick = Some(self.tick);
                }
            }
            // Update surprise
            room.surprise = (room.reported_vibe - room.vibe).abs();
        }
    }

    /// Single simulation step
    pub fn step(&mut self) {
        // Gather neighbor vibes (all other rooms)
        let neighbor_data: Vec<(usize, f64, f64)> = self.rooms.iter()
            .map(|r| (r.id, r.influence_weight, r.reported_vibe))
            .collect();

        let fleet = self.fleet_vibe();

        for room in &mut self.rooms {
            let neighbors: Vec<(usize, f64)> = neighbor_data.iter()
                .filter(|(id, _, _)| *id != room.id)
                .map(|(id, w, _v)| (*id, *w))
                .collect();
            room.report(fleet, &neighbors);
        }

        // Recompute fleet vibe with new reports
        let fleet = self.fleet_vibe();
        self.fleet_vibe_history.push(fleet);
        self.surprise_history.push(self.fleet_surprise());

        // Update vibes
        for room in &mut self.rooms {
            room.update_vibe(fleet);
        }

        // JEPA detection
        self.jepa_detect();

        // Check convergence (only for honest rooms)
        let honest_vibes: Vec<f64> = self.rooms.iter()
            .filter(|r| r.attack == AttackType::Honest)
            .map(|r| r.vibe)
            .collect();
        if !honest_vibes.is_empty() {
            let honest_mean: f64 = honest_vibes.iter().sum::<f64>() / honest_vibes.len() as f64;
            let max_deviation = honest_vibes.iter().map(|v| (v - honest_mean).abs()).fold(0.0_f64, f64::max);
            if max_deviation < CONVERGENCE_THRESHOLD && self.converged_tick.is_none() {
                self.converged_tick = Some(self.tick);
            }
        }

        // Decay influence weights for flagged rooms (recovery mechanism)
        for room in &mut self.rooms {
            if room.flagged_anomalous {
                room.influence_weight *= INFLUENCE_DECAY;
            }
        }

        self.tick += 1;
    }

    /// Run the full simulation
    pub fn run(&mut self) {
        for _ in 0..self.max_ticks {
            self.step();
        }
    }

    /// Remove attackers and continue running
    pub fn remove_attackers_and_run(&mut self, additional_ticks: usize) {
        for room in &mut self.rooms {
            if room.attack != AttackType::Honest {
                room.attack = AttackType::Honest;
                room.vibe = 0.5;
                room.flagged_anomalous = false;
                room.anomaly_tick = None;
                room.influence_weight = 1.0 / ROOM_COUNT as f64;
            }
        }
        self.converged_tick = None;
        for _ in 0..additional_ticks {
            self.step();
        }
    }
}

// ─── Results ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct SimulationResult {
    pub attack_type: AttackType,
    pub attacker_count: usize,
    pub convergence_tick: Option<usize>,
    pub final_fleet_vibe: f64,
    pub fleet_vibe_distortion: f64,
    pub max_surprise: f64,
    pub mean_surprise: f64,
    pub detection_ticks: Vec<usize>,
    pub all_detected: bool,
    pub fast_detection: bool, // < 100 ticks
}

impl fmt::Display for SimulationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:<15} attackers={:<2} converge={:<5} distortion={:.4} max_surprise={:.4} detected={}/{}",
            self.attack_type.name(),
            self.attacker_count,
            self.convergence_tick.map(|t| t.to_string()).unwrap_or_else(|| "never".to_string()),
            self.fleet_vibe_distortion,
            self.max_surprise,
            self.detection_ticks.len(),
            self.attacker_count,
        )
    }
}

// ─── Benchmarking ────────────────────────────────────────────────────────────

pub struct Benchmarks {
    pub baseline_fleet_vibe: f64,
    pub baseline_convergence_tick: Option<usize>,
    pub baseline_surprise: f64,
}

impl Benchmarks {
    pub fn compute() -> Self {
        let mut sim = Simulation::new(DEFAULT_TICKS, &[]);
        sim.run();
        let baseline_fleet_vibe = sim.fleet_vibe_history.last().copied().unwrap_or(0.5);
        let baseline_convergence_tick = sim.converged_tick;
        let baseline_surprise = sim.surprise_history.iter().sum::<f64>() / sim.surprise_history.len().max(1) as f64;
        Self {
            baseline_fleet_vibe,
            baseline_convergence_tick,
            baseline_surprise,
        }
    }

    pub fn run_attack(&self, attack: AttackType, attacker_ids: &[usize], ticks: usize) -> SimulationResult {
        let profiles: Vec<(usize, AttackType)> = attacker_ids.iter().map(|id| (*id, attack)).collect();
        let mut sim = Simulation::new(ticks, &profiles);
        sim.run();

        let convergence_tick = sim.converged_tick;
        let final_fleet_vibe = sim.fleet_vibe_history.last().copied().unwrap_or(0.5);
        let fleet_vibe_distortion = (final_fleet_vibe - self.baseline_fleet_vibe).abs();
        let max_surprise = sim.surprise_history.iter().cloned().fold(0.0_f64, f64::max);
        let mean_surprise = sim.surprise_history.iter().sum::<f64>() / sim.surprise_history.len().max(1) as f64;

        let detection_ticks: Vec<usize> = sim.rooms.iter()
            .filter(|r| r.attack != AttackType::Honest && r.anomaly_tick.is_some())
            .map(|r| r.anomaly_tick.unwrap())
            .collect();
        let all_detected = detection_ticks.len() >= attacker_ids.len();
        let fast_detection = detection_ticks.iter().all(|&t| t < 100);

        SimulationResult {
            attack_type: attack,
            attacker_count: attacker_ids.len(),
            convergence_tick,
            final_fleet_vibe,
            fleet_vibe_distortion,
            max_surprise,
            mean_surprise,
            detection_ticks,
            all_detected,
            fast_detection,
        }
    }

    /// Run recovery test: attack, then remove, measure recovery ticks
    pub fn run_recovery(&self, attack: AttackType, attacker_ids: &[usize], ticks_before: usize, ticks_after: usize) -> usize {
        let profiles: Vec<(usize, AttackType)> = attacker_ids.iter().map(|id| (*id, attack)).collect();
        let mut sim = Simulation::new(ticks_before, &profiles);
        sim.run();
        // Remove attackers
        sim.remove_attackers_and_run(ticks_after);
        // How many ticks after removal to converge?
        // converged_tick is reset in remove_attackers_and_run
        // We look at the last ticks_after ticks of fleet_vibe_history
        let history = &sim.fleet_vibe_history;
        let post_start = history.len() - ticks_after;
        for i in post_start..history.len() {
            let window = &history[post_start..=i];
            if window.len() < 10 { continue; }
            let mean: f64 = window.iter().sum::<f64>() / window.len() as f64;
            let max_dev = window.iter().map(|v| (v - mean).abs()).fold(0.0_f64, f64::max);
            if max_dev < CONVERGENCE_THRESHOLD {
                return i - post_start;
            }
        }
        ticks_after // didn't recover
    }

    /// Breakpoint test: does damage scale superlinearly with attacker count?
    pub fn run_breakpoint(&self, attack: AttackType, max_attackers: usize) -> Vec<(usize, f64)> {
        let mut results = Vec::new();
        for count in 0..=max_attackers {
            let attacker_ids: Vec<usize> = (0..count).collect();
            let result = self.run_attack(attack, &attacker_ids, DEFAULT_TICKS);
            results.push((count, result.fleet_vibe_distortion));
        }
        results
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

mod tests;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║   Grand Pattern Adversarial Testing Suite                  ║");
    println!("║   {} rooms, {} ticks, {:.0}% attackers                    ║",
        ROOM_COUNT, DEFAULT_TICKS, ATTACKER_RATIO * 100.0);
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let benchmarks = Benchmarks::compute();
    println!("── Baseline (no attackers) ──");
    println!("  Fleet vibe:     {:.4}", benchmarks.baseline_fleet_vibe);
    println!("  Converged at:   {:?}", benchmarks.baseline_convergence_tick);
    println!("  Mean surprise:  {:.6}", benchmarks.baseline_surprise);
    println!();

    // Single attacker at room 0
    let attacker_ids = vec![0];

    println!("── Single Attacker Results ──");
    println!("{:<15} {:<12} {:<8} {:<12} {:<12} {:<8} {:<8}",
        "Attack", "Converge@T", "FleetV", "Distortion", "MaxSurprise", "Detect", "Fast?");
    println!("{}", "─".repeat(85));

    let mut results: Vec<SimulationResult> = Vec::new();
    for attack in AttackType::all_attacks() {
        let result = benchmarks.run_attack(*attack, &attacker_ids, DEFAULT_TICKS);
        println!("{}", result);
        results.push(result);
    }

    println!();

    // Collusion test: 2 coordinated attackers
    println!("── Collusion Test (2 synchronized attackers) ──");
    let collusion_ids = vec![0, 1];
    let collusion_result = benchmarks.run_attack(AttackType::Collusion, &collusion_ids, DEFAULT_TICKS);
    let single_collusion = benchmarks.run_attack(AttackType::Collusion, &[0], DEFAULT_TICKS);
    let damage_ratio = if single_collusion.fleet_vibe_distortion > 0.0 {
        collusion_result.fleet_vibe_distortion / single_collusion.fleet_vibe_distortion
    } else {
        0.0
    };
    println!("  Single attacker distortion: {:.4}", single_collusion.fleet_vibe_distortion);
    println!("  Double attacker distortion: {:.4}", collusion_result.fleet_vibe_distortion);
    println!("  Damage ratio (2x/1x):       {:.2}x", damage_ratio);
    println!("  Superlinear?                {}", if damage_ratio > 2.0 { "YES ⚠️" } else { "no" });
    println!();

    // Breakpoint test
    println!("── Breakpoint Analysis (Contrarian, 1-5 attackers) ──");
    let breakpoints = benchmarks.run_breakpoint(AttackType::Contrarian, 5);
    for (count, distortion) in &breakpoints {
        println!("  {} attacker(s): distortion = {:.4} {}", 
            count, distortion, 
            if *count > 1 && *distortion > breakpoints[1].1 * *count as f64 { "⚠️ superlinear" } else { "" });
    }
    println!();

    // Recovery test
    println!("── Recovery After Attacker Removal ──");
    for attack in AttackType::all_attacks() {
        let recovery_ticks = benchmarks.run_recovery(*attack, &[0], 500, 500);
        println!("  {:<15}: recovered in {} ticks", attack.name(), recovery_ticks);
    }
    println!();

    // Key findings
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║   Key Findings                                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let most_disruptive = results.iter().max_by(|a, b| a.fleet_vibe_distortion.partial_cmp(&b.fleet_vibe_distortion).unwrap()).unwrap();
    println!("  Most disruptive attack:    {} (distortion: {:.4})", most_disruptive.attack_type.name(), most_disruptive.fleet_vibe_distortion);

    let fastest_detected = results.iter()
        .filter(|r| !r.detection_ticks.is_empty())
        .min_by_key(|r| r.detection_ticks.iter().min().unwrap_or(&1000))
        .unwrap();
    println!("  Fastest detected:          {} (tick {})", fastest_detected.attack_type.name(), fastest_detected.detection_ticks.iter().min().unwrap_or(&0));

    let all_fast = results.iter().filter(|r| r.fast_detection).count();
    println!("  Fast detection (<100t):    {}/{} attacks", all_fast, results.len());

    println!("  Fleet recovers after attacker removal (see recovery table above)");
}
