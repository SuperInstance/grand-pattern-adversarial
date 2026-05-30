# grand-pattern-adversarial

> Adversarial testing — can a malicious room disrupt fleet convergence?

Pure Rust, zero dependencies. Simulates a fleet of rooms exchanging a mono-dimensional "vibe" (f64 in [0,1]) with JEPA (weighted history) prediction.

## Attacks (8)

| # | Attack | Strategy |
|---|--------|----------|
| 1 | Constant Max | Always emits 1.0 |
| 2 | Constant Min | Always emits 0.0 |
| 3 | Oscillator | Alternates between 0 and 1 |
| 4 | Random Noise | Deterministic pseudo-random output |
| 5 | Amplifier | Outputs 2× fleet vibe |
| 6 | Mimic | Copies best honest neighbor |
| 7 | Contrarian | Pushes hard opposite to fleet mean |
| 8 | Collusion | 2 coordinated rooms oscillating in phase |

## Metrics

10 rooms, 1000 ticks, 1-2 attackers per simulation:

- **Convergence delay** — how many ticks until fleet reaches 0.5 ± 0.05
- **Fleet vibe distortion** — max deviation from target (0.5)
- **Surprise pollution** — JEPA prediction error from attackers
- **Detection speed** — how fast sustained surprise is identified
- **Recovery speed** — convergence after attacker removal

## Tests (15)

```
test_constant_max, test_constant_min, test_oscillator,
test_random_noise, test_amplifier, test_mimic, test_contrarian,
test_collusion, test_contrarian_max_disruption,
test_jepa_detects_constant_attackers, test_recovery_after_removal,
test_collusion_greater_than_2x, test_detection_speed,
test_deterministic, test_baseline_converges
```

## Run

```bash
cargo test
```
