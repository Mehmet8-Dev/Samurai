---
name: samurai-scenario-author
description: Author, validate, compile in-process, execute live, and SLA-verify multi-step Web/Mobile persona JSON scenarios (HTTP/1.1, HTTP/2, QUIC/H3, cookie/JWT token binding, think-time distributions) using Samurai's native Scenario Engine MCP tools.
---

# Samurai Multi-Step Persona Scenario Authoring Skill

Use this skill to model realistic multi-step user journeys (login -> token capture -> browse -> checkout) instead of synthetic single-URL floods.

## Authoritative Scenario JSON Structure

Scenarios must be valid **JSON** (never YAML at runtime):
- `schema_version`: `1`
- `protocol`: `"http1"` | `"http2"` | `"http3"` (or `"quic"`)
- `personas`: Map of client profiles (`device_profile`: `"web"`/`"mobile"`, `headers`, `cookies`, `weight`, `timeout_policy`, `retry_policy`)
- `flows`: Map of ordered workflows bound to a `persona`, containing `steps`:
  - `request`: `method`, `path`, `body_template`, `headers`, plus dynamic token binding (`token_source`: `"cookie"` | `"header"` | `"body_json"`, `token_path`, `token_variable_name`, `extract_token_regex`)
  - `pause`: `think_time` (`min_ms`, `max_ms`, `distribution`: `"uniform"` | `"normal"` | `"exponential"` | `"pareto"`)
  - `end_session`: clean connection teardown
  - L4/L7 primitives: `tcp_connect`, `tcp_send`, `tcp_expect`, `tcp_close`, `tls_connect`, `dns_resolve`, `dhcp_acquire`, `arp_resolve`, `igmp_join`, `ipv6_nd_solicit`
- `load_model`: `backend`, `concurrent_vus`, `ramp_seconds`
- `sla`: `min_completion_rate`, `max_step_fail_ratio`, `max_latency_p95_ms`, `max_connect_timeout_ratio`, `max_retransmit_ratio`

## 3-Step Verification Workflow

1. **Compile & Validate First (Zero Network Traffic):** Call `samurai_scenario_compile` with your inline `scenario` JSON, `workers`, and `sessions_per_worker` to validate syntax, persona weights, and SoA session compilation in-process.
2. **Execute Live (Fail-Closed Lab Target):** Call `samurai_scenario_run` against `127.0.0.1` or an RFC 1918 lab host to run `samurai_scenario_worker` over real stateful HTTP/1.1, HTTP/2, or QUIC connections.
3. **Verify SLA Contract:** Call `samurai_scenario_evaluate_sla` on observed session/step/latency/TCP counters to get a deterministic pass/fail verdict.
