---
name: samurai-autopilot-rl
description: Drive Samurai's Closed-Loop Autopilot (AIMD, Binary Search, and Mahoraga RL + SRLP MLP/RL^2 GRU policies) with native SLO jump-cap protection, LeverShield WAF path-block reflexes, long-window scenario/L7 soak runs, and per-call target authorization via MCP.
---

# Samurai Closed-Loop Autopilot & Mahoraga RL Skill

Use this skill to discover a system-under-test's sustainable SLO ceiling, run closed-loop capacity soak tests (`window_s` 0.2–3600s), drive real multi-step scenarios inside closed-loop windows, or couple an external RL/LLM agent to Samurai's native safety shields.

## Available Strategies

- **`binsearch`**: Deterministic exponential bracketing + bisection to locate maximum SLO-green RPS in a bounded number of windows (best for CI capacity gates).
- **`aimd`**: Additive-increase / multiplicative-decrease controller that converges to and holds the sustainable ceiling during sustained soak tests.
- **`rl` (Mahoraga)**: Native SRLP policy (Feedforward MLP or **RL^2 GRU** recurrent context encoder loaded via `policy_path`) OR an external RL/LLM agent proposing `rl_action_rps` and extra 7-D shaping levers (`concurrency`, `request_mix`, `source_rotation`, `pacing_mode`, `auth_mode`, `evasion_tactic`).

## Native Safety Shields (Always Active)

1. **RPS Jump-Cap & SLO Backoff (`ClosedLoopController::StepRl`):** Caps upward RPS jumps to `rl_max_jump_factor` (default `2.0x`) on healthy windows and enforces multiplicative backoff (`aimd_backoff`, default `0.5x`) whenever error %, wire loss %, P99 latency, rate accuracy, or 429/503 `pushback_pct` violates SLO.
2. **WAF Path-Block Reflex (`LeverShield`):** Tracks per-variant 2xx `success_ratio`; if a `request_mix` variant drops below `honored_success_floor` (default `0.10`), automatically substitutes the best-known honored or unobserved variant.
3. **Ban-Pressure EWMA:** Smooths `conn_drop_ratio` (`alpha = 0.5`) to flag persistent IP/session bans.

## Workflow (Standalone L7 or Full Scenario Closed-Loop)

1. **Create Session (`samurai_autopilot_create`):** Specify `strategy` (`aimd` | `binsearch` | `rl`), `min_rps`, `max_rps`, SLO thresholds (`slo_max_error_pct`, `slo_max_latency_ms`, `slo_max_pushback_pct`, etc.), and optional `policy_path` / `explore: true`.
2. **Drive Windows:**
   - **Live Dataplane Mode (`samurai_autopilot_run_window`):**
     - Executes a live test window at `current_setpoint_rps` using either `worker: "l7"` (or other allowed workers) OR multi-step `scenario` / `scenario_file` (switches default worker to `"scenario"`).
     - `window_s` supports `0.2` to `3600.0` seconds; when `window_s > 15s` with `"scenario"`, automatically enables time-based `duration_s` soak for the window.
     - Automatically auto-sizes `timeout_s` above `window_s` (up to `max_timeout_s`, default `86400s`) and forwards per-call `allow_target` / `allow_targets` for authorized external hosts.
   - **External Metrics Mode (`samurai_autopilot_step`):** Feed externally observed `actual_rps`, `attempted`, `errors`, `latency_p99_ms`, `rate_limited_ratio`, `overload_ratio`, `variant_applied`, `success_ratio`, `rl_action_rps`, and `rl_levers` to obtain the next shielded 7-D action.
3. **Monitor & Reset:** Call `samurai_autopilot_status` to inspect convergence, `best_slo_green_rps`, and `LeverShield` state; call `samurai_autopilot_reset` (with `delete: true` to remove or `false` to reset `RL^2 GRU` hidden state).

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Proposed `rl_action_rps` ignored / capped | Exceeded `rl_max_jump_factor` or violated SLO | Check returned `decision.reason` and tune SLO thresholds or `rl_max_jump_factor`. |
| Variant immediately switched by `LeverShield` | `success_ratio < honored_success_floor` (0.10) | Normal defensive reflex; check endpoint 403/429 rules or raise/adjust `honored_success_floor` only if intentional. |
| External target blocked in `run_window` | Missing authorization parameter | Pass `allow_target` or `allow_targets` directly in `samurai_autopilot_run_window`. |
| Long soak window hits count cap | Exceeded default `100M` count budget | Raise/disable limit with `SAMURAI_MCP_MAX_COUNT=0` or reduce `target_rps * window_s`. |
