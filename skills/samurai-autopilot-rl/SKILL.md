---
name: samurai-autopilot-rl
description: Drive Samurai's Closed-Loop Autopilot (AIMD, Binary Search, and Mahoraga RL + SRLP MLP/RL^2 GRU policies) with native SLO jump-cap protection and LeverShield WAF path-block reflexes via MCP.
---

# Samurai Closed-Loop Autopilot & Mahoraga RL Skill

Use this skill to find a system-under-test's sustainable SLO ceiling, run closed-loop capacity soak tests, or connect an external RL / LLM policy agent to Samurai's native safety shield.

## Available Strategies

- **`binsearch`**: Deterministic exponential bracketing + bisection to find the maximum SLO-green RPS in a bounded number of windows (best for CI capacity gates).
- **`aimd`**: Additive-increase / multiplicative-decrease controller that converges to and holds the sustainable ceiling during long soak runs.
- **`rl` (Mahoraga)**: Learned native SRLP policy (Feedforward MLP or **RL² GRU** recurrent context encoder loaded via `policy_path`) OR an external RL/LLM agent proposing `rl_action_rps` and extra 7-D shaping levers (`concurrency`, `request_mix`, `source_rotation`, `pacing_mode`, `auth_mode`, `evasion_tactic`).

## Native Safety Shields (Always Active)

1. **RPS Jump-Cap & SLO Backoff (`ClosedLoopController::StepRl`):** Caps upward RPS jumps to `rl_max_jump_factor` (default `2.0x`) on healthy windows and forces multiplicative backoff (`aimd_backoff`, default `0.5x`) whenever error %, wire loss %, P99 latency, rate accuracy, or 429/503 `pushback_pct` violates SLO.
2. **WAF Path-Block Reflex (`LeverShield`):** Tracks per-variant best 2xx `success_ratio`; if a `request_mix` variant drops below `honored_success_floor` (default `0.10`), automatically substitutes the best-known honored or unobserved variant.
3. **Ban-Pressure EWMA:** Continuously smooths `conn_drop_ratio` (`alpha = 0.5`) to detect persistent IP/session bans.

## Workflow

1. Call `samurai_autopilot_create` with strategy, `min_rps`/`max_rps`, SLO thresholds, and optional `policy_path` / `explore: true`.
2. Loop either:
   - `samurai_autopilot_run_window` (executes a live safety-gated dataplane window at `current_setpoint_rps`, parses JSON telemetry, and steps automatically), OR
   - `samurai_autopilot_step` (feeds externally measured window metrics + optional `rl_action_rps`/`rl_levers` and returns the shielded 7-D action).
3. Inspect progress with `samurai_autopilot_status` and clean up or start a fresh episode (`ResetContext`) with `samurai_autopilot_reset`.
