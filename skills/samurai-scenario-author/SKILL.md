---
name: samurai-scenario-author
description: Author, validate, compile in-process, execute live, and SLA-verify multi-step Web/Mobile persona JSON scenarios (HTTP/1.1, HTTP/2, QUIC/H3, L4 TCP, cookie/JWT token binding, expected_status assertions, and time-based soak) using Samurai's native Scenario Engine MCP tools.
---

# Samurai Multi-Step Persona Scenario Authoring Skill

Use this skill to model realistic multi-step user journeys (login -> JWT/cookie capture -> authenticated calls -> assertions) or L4 TCP request/expectation sessions using `samurai_scenario_compile`, `samurai_scenario_run`, and `samurai_scenario_evaluate_sla`.

## Authoritative Scenario JSON Structure

Scenarios must be valid **JSON** (never YAML at runtime):
- `schema_version`: `1`
- `protocol`: `"http1"` | `"http2"` | `"http3"` | `"quic"` | `"tcp"` (use `"tcp"` when testing non-HTTP services such as Redis/PostgreSQL/custom TCP)
- `personas`: Map of client profiles (`device_profile`: `"web"`/`"mobile"`, `headers`, `cookies`, `weight`, `timeout_policy`, `retry_policy`)
- `flows`: Map of ordered workflows bound to a `persona`, containing `steps` (step type field supports either `"kind"` or `"type"`):
  - **Runtime-Executed HTTP Steps:**
    - `request`: `method`, `path`, `body_template`, `headers`, plus:
      - **Token Capture:** `token_variable_name`, `token_source` (`"cookie"` | `"header"` | `"body_json"` | `"regex"`), `token_path` (e.g. `"data.accessToken"` for `body_json`, or header name for `header`), `extract_token_regex` (works standalone without `token_path`). Interpolate captured values cleanly in subsequent steps via `{{token_variable_name}}`.
      - **Assertions:** `expected_status` (integer `200`, `{ "min": 200, "max": 299 }`, or `[200, 299]`; also accepts `expect_status_min` / `expect_status_max`), `expect_body_contains`, `expect_header` (`{ "name": "...", "value": "..." }`).
    - `pause`: `think_time` (`min_ms`, `max_ms`, `distribution`: `"uniform"` | `"normal"` | `"exponential"` | `"pareto"`, `mean_ms`, `stddev_ms`)
    - `end_session`: clean flow termination (`GET /` is never emitted for `end_session`)
  - **Runtime-Executed L4 TCP Steps** (activated automatically when `protocol: "tcp"` or flows contain `tcp_*` without HTTP `request` steps):
    - `tcp_connect` (`dst_port` optional override, `timeout_ms`)
    - `tcp_send` (`payload_template` or `body_template`)
    - `tcp_expect` (`condition` substring match, `timeout_ms`)
    - `tcp_close`
  - **Compile-Only Primitives (Do Not Rely on Runtime Execution Yet):**
    - `tls_connect`, `tls_disconnect`, `dns_resolve`, `dhcp_acquire`, `dhcp_release`, `arp_resolve`, `igmp_join`, `igmp_leave`, `ipv6_nd_solicit`, `branch`, `loop`, `assert` are parsed and validated into compiled SoA metrics by `samurai_scenario_compile`, **not** executed as live traffic steps by `samurai_scenario_worker`. Use `request` + `scheme: "https"` for TLS HTTP tests, and `duration_s` for repetition instead of `loop`.
- `load_model`: `backend` (`"l7"` / `"http"`), `concurrent_vus`, `ramp_seconds`, optional `duration_s` (time-based soak in seconds; can also be passed top-level on `samurai_scenario_run`)
- `sla`: `min_completion_rate`, `max_step_fail_ratio`, `max_latency_p95_ms`, `max_connect_timeout_ratio`, `max_retransmit_ratio`

## Ready-to-Use Scenario Templates

### 1. HTTP/1.1 Login -> JWT (`body_json`) -> Authenticated GET + Assertions
```json
{
  "target": "127.0.0.1",
  "port": 3000,
  "count": 100,
  "scenario": {
    "schema_version": 1,
    "protocol": "http1",
    "personas": {"api_user": {"device_profile": "web", "weight": 1}},
    "flows": {
      "auth_flow": {
        "persona": "api_user",
        "steps": [
          {
            "kind": "request",
            "method": "POST",
            "path": "/api/auth/login",
            "headers": {"Content-Type": "application/json"},
            "body_template": "{\"email\":\"user@example.com\",\"password\":\"pass\"}",
            "token_source": "body_json",
            "token_path": "data.accessToken",
            "token_variable_name": "jwt",
            "expected_status": 200
          },
          {
            "kind": "request",
            "method": "GET",
            "path": "/api/profile",
            "headers": {"Authorization": "Bearer {{jwt}}"},
            "expected_status": {"min": 200, "max": 299},
            "expect_body_contains": "email"
          },
          {"kind": "end_session"}
        ]
      }
    },
    "load_model": {"backend": "l7", "concurrent_vus": 8},
    "sla": {"min_completion_rate": 0.99, "max_step_fail_ratio": 0.01, "max_latency_p95_ms": 250}
  }
}
```

### 2. L4 Raw TCP (`tcp_connect` -> `tcp_send` -> `tcp_expect` -> `tcp_close`)
```json
{
  "target": "127.0.0.1",
  "port": 6379,
  "count": 20,
  "scenario": {
    "schema_version": 1,
    "protocol": "tcp",
    "personas": {"redis_client": {"device_profile": "web", "weight": 1}},
    "flows": {
      "redis_ping": {
        "persona": "redis_client",
        "steps": [
          {"kind": "tcp_connect", "timeout_ms": 1000},
          {"kind": "tcp_send", "payload_template": "PING\r\n"},
          {"kind": "tcp_expect", "condition": "+PONG", "timeout_ms": 1000},
          {"kind": "tcp_close"}
        ]
      }
    },
    "load_model": {"backend": "l7", "concurrent_vus": 4},
    "sla": {"min_completion_rate": 1.0, "max_step_fail_ratio": 0.0, "max_latency_p95_ms": 100}
  }
}
```

## 4-Step Verification, External Targets & Soak Workflow

1. **Compile First (Zero Traffic):** Call `samurai_scenario_compile` with `scenario` (or `scenario_file`), `workers`, and `sessions_per_worker` to validate syntax and SoA compilation.
2. **Execute Live (`samurai_scenario_run`):**
   - Internal targets (`127.0.0.0/8`, RFC 1918, `host.docker.internal`) work directly.
   - Authorized external IPv4s, CIDRs, or domain names require `allow_target` or `allow_targets` (e.g., `"allow_target": "api.staging.example.com"`).
   - For sustained soak tests, set `duration_s` (e.g. `duration_s: 300`, up to `86400s`) and optionally `async: true`, then poll `samurai_job_status` / stop with `samurai_job_stop`.
3. **Inspect `scenario_telemetry` (Not Just Transport `errors`):** Always check `status_2xx..5xx`, `status_codes`, `expectation_failures`, `soak_rounds`, `elapsed_s`, `step_results`, and `scenario_sla_passed`.
4. **Independent SLA Verification:** Pass observed counters into `samurai_scenario_evaluate_sla` if combining multi-node or custom counters.

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Bearer token sent empty (`Bearer `) | Wrong `token_path` or missing `token_source` | Verify JSON response path (`data.accessToken`) with `token_source: "body_json"`, or omit `token_path` when using `extract_token_regex`. |
| `401`/`500` returned but `errors: 0` | Transport succeeded; no status expectation | Set `expected_status: 200` (or `{min, max}`) on steps and check `scenario_telemetry.status_4xx` / `expectation_failures`. |
| L4 TCP scenario reports `sent: 0` | Mixed HTTP + TCP steps in one flow or old worker | Set `protocol: "tcp"` and keep only `tcp_*` / `pause` / `end_session` steps in L4 flows. |
| External domain/IP rejected | Fail-closed safety gate | Pass `allow_target` (or `allow_targets`) matching target domain/IP/CIDR. |
