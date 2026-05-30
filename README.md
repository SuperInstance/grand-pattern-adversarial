# Grand Pattern Adversarial Testing

> Can a single malicious room disrupt fleet convergence?

Adversarial testing suite for the Grand Pattern vibe consensus system. Pure Rust, zero dependencies.

## Attacks Tested (8)

| Attack | Strategy |
|--------|----------|
| **Constant Max** | Always reports vibe at maximum (1.0) |
| **Constant Min** | Always reports vibe at minimum (0.0) |
| **Oscillator** | Alternates between max and min every tick |
| **Random Noise** | Reports deterministic PRNG-based random vibes |
| **Amplifier** | Reports 2× fleet vibe (positive feedback) |
| **Mimic** | Copies most influential neighbor |
| **Contrarian** | Always reports inverse of fleet vibe |
| **Collusion** | Two rooms oscillate in sync |

## Metrics (10 rooms, 1000 ticks, 10% attackers)

1. **Convergence delay** — extra ticks to converge vs baseline
2. **Fleet vibe distortion** — distance from baseline fleet vibe
3. **Surprise pollution** — attacker's effect on fleet surprise
4. **Detection speed** — ticks until JEPA flags the attacker
5. **Recovery speed** — ticks to recover after attacker removal

## Key Findings

Run the suite to see results:

```bash
cargo run
cargo test
```

## Design

- **Fleet vibe**: weighted average of all room reports
- **Convergence**: honest rooms within 0.02 of each other
- **JEPA detection**: rooms > 2σ from fleet mean are flagged
- **Influence decay**: flagged rooms lose weight each tick (×0.95)
- **Deterministic**: all runs are reproducible (xorshift64 PRNG)

## Tests (18)

```bash
cargo test -- --nocapture
```

All tests are deterministic — run twice, get identical results.

## License

MIT
