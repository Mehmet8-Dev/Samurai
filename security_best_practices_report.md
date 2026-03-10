# Security Best Practices Report - Samurai

## Executive Summary
This repository has a strong functional baseline (JWT auth, password hashing, ownership checks on run/log endpoints), but there are multiple high-impact security risks around secret management, privileged bootstrap, abuse controls, and production hardening. The most urgent issues are insecure JWT secret defaults, first-user-admin bootstrap takeover risk, and unconstrained workload parameters that can be abused for resource exhaustion.

## Critical Findings

### SBP-001: Insecure JWT secret defaults enable token forgery if not overridden
- Severity: Critical
- Location: `ddos_samurai/saas_auth.py:18`, `docker-compose.yml:33`
- Evidence:
  - `JWT_SECRET = os.getenv("SAMURAI_JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")`
  - `SAMURAI_JWT_SECRET: change-this-in-prod`
- Impact: If production uses defaults or weak values, attackers can forge valid bearer tokens and impersonate users/admins.
- Fix:
  - Fail fast at startup unless `SAMURAI_JWT_SECRET` is set to a strong value in non-dev environments.
  - Use a secrets manager and rotate compromised keys.
- Mitigation:
  - Add key versioning (`kid`) and key rotation playbook.
  - Alert on sudden token validation anomalies.
- False positive notes:
  - If deployment always injects strong secrets and never uses compose defaults outside local dev, practical risk is reduced.

## High Findings

### SBP-002: First registrant automatically receives admin role (bootstrap takeover risk)
- Severity: High
- Location: `ddos_samurai/api.py:366`, `ddos_samurai/api.py:371`, `README.md:60`
- Evidence:
  - `first_user = db.scalar(select(func.count(User.id))) == 0`
  - `role=UserRole.ADMIN if first_user else UserRole.USER`
  - README: "İlk kullanıcı otomatik olarak `admin` rolüyle oluşturulur."
- Impact: On fresh internet-exposed deployments, an attacker can race the first registration and permanently capture admin privileges.
- Fix:
  - Replace first-user auto-admin with explicit bootstrap token or one-time out-of-band admin provisioning.
- Mitigation:
  - Restrict `/auth/register` during bootstrap phase.
- False positive notes:
  - Lower risk if deployment is always private during first initialization.

### SBP-003: Any authenticated user can explicitly enable public target traffic
- Severity: High
- Location: `ddos_samurai/saas_schemas.py:104`, `ddos_samurai/api.py:311`, `ddos_samurai/utils.py:544`
- Evidence:
  - API model includes `allow_public_target: bool = False`.
  - API forwards `--allow-public-target` when requested.
  - Safety gate then allows public destinations when this flag is true.
- Impact: Compromised or malicious accounts can direct high-rate traffic toward internet hosts, creating legal/abuse and platform-risk exposure.
- Fix:
  - Gate `allow_public_target` behind admin-only policy, explicit per-tenant entitlements, and approval workflow.
- Mitigation:
  - Enforce destination allowlists and per-account rate ceilings server-side.
- False positive notes:
  - If this behavior is intentionally allowed for all tenants, classify as accepted risk and document compensating controls.

### SBP-004: Unbounded test parameters allow authenticated resource exhaustion
- Severity: High
- Location: `ddos_samurai/saas_schemas.py:78`, `ddos_samurai/saas_schemas.py:79`, `ddos_samurai/saas_schemas.py:80`, `ddos_samurai/saas_schemas.py:81`, `ddos_samurai/api.py:696`
- Evidence:
  - `count`, `duration`, `workers`, `rps`, `http_concurrency` are accepted without upper bounds.
  - Requests spawn subprocess workloads directly.
- Impact: An authenticated user can submit extreme values and exhaust CPU/RAM/network, degrading service for all tenants.
- Fix:
  - Add strict max constraints in `TestStartRequest` and server-side policy enforcement by plan.
  - Add global/tenant concurrency quotas and job queueing.
- Mitigation:
  - Circuit breakers for process count, pps/rps ceilings, and per-user budget caps.
- False positive notes:
  - If an external orchestrator already caps these values, verify and document it in-code.

### SBP-005: Missing brute-force protections on login endpoint
- Severity: High
- Location: `ddos_samurai/api.py:388`, `ddos_samurai/api.py:397`, `ddos_samurai/api.py:398`
- Evidence:
  - Login validates credentials and increments a counter, but no lockout/backoff/rate limit is enforced.
- Impact: Increases feasibility of credential stuffing/password spraying against user accounts.
- Fix:
  - Add IP/account-based rate limits and progressive backoff.
  - Add temporary account lock or step-up challenge after repeated failures.
- Mitigation:
  - Alerting on anomalous failure bursts via auth metrics.
- False positive notes:
  - Risk is lower if robust rate limiting is guaranteed at API gateway/WAF level.

## Medium Findings

### SBP-006: CORS defaults are overly permissive with credentials allowed
- Severity: Medium
- Location: `ddos_samurai/api.py:83`, `ddos_samurai/api.py:87`
- Evidence:
  - Default origins derive from `"*"` and middleware is configured with `allow_credentials=True`.
- Impact: Misconfigured deployments may unintentionally trust arbitrary origins, increasing cross-origin attack surface.
- Fix:
  - Remove wildcard defaults; require explicit allowlist per environment.
  - Block startup when `allow_credentials=True` and wildcard origins are detected.
- Mitigation:
  - Environment validation checks in startup.
- False positive notes:
  - In current compose, origins are restricted to localhost.

### SBP-007: Client IP attribution trusts spoofable `X-Forwarded-For`
- Severity: Medium
- Location: `ddos_samurai/api.py:233`, `ddos_samurai/api.py:235`
- Evidence:
  - Client IP is taken from `x-forwarded-for` without trusted-proxy validation.
- Impact: Attackers can spoof origin in security logs, reducing incident response reliability.
- Fix:
  - Only trust forwarding headers from known reverse proxies.
  - Otherwise use socket peer IP.
- Mitigation:
  - Add proxy chain validation and canonical client IP extraction utility.
- False positive notes:
  - If a trusted ingress strips/replaces this header, risk is reduced.

### SBP-008: Bearer token persisted in `localStorage`
- Severity: Medium
- Location: `dashboard/src/hooks/useAuth.jsx:11`, `dashboard/src/hooks/useAuth.jsx:37`, `dashboard/src/api/client.js:22`
- Evidence:
  - Token is read/written from `localStorage` and attached as Authorization header.
- Impact: Any successful XSS in the dashboard can exfiltrate long-lived tokens.
- Fix:
  - Prefer HttpOnly secure cookies for session transport where feasible.
  - If keeping bearer tokens, shorten TTL and implement refresh + rotation.
- Mitigation:
  - Deploy strict CSP and reduce XSS sink exposure.
- False positive notes:
  - Risk depends on XSS exposure and token lifetime.

### SBP-009: Missing baseline browser security headers in dashboard nginx config
- Severity: Medium
- Location: `dashboard/nginx.conf:1`
- Evidence:
  - No explicit CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, or Referrer-Policy headers.
- Impact: Weaker browser-side defenses against XSS impact amplification and clickjacking.
- Fix:
  - Add hardened response headers in nginx (with CSP tuned to app assets).
- Mitigation:
  - Validate header posture in CI smoke tests.
- False positive notes:
  - If an upstream gateway injects these headers consistently, this may be partially mitigated.

## Existing Good Controls Observed
- Passwords are hashed using passlib bcrypt: `ddos_samurai/saas_auth.py:22`, `ddos_samurai/api.py:370`.
- Ownership checks exist for run/log access: `ddos_samurai/api.py:827`, `ddos_samurai/api.py:915`.
- CLI safety gate blocks public targets by default unless explicitly overridden: `ddos_samurai/utils.py:540`, `ddos_samurai/utils.py:547`.

## Recommended Fix Order
1. SBP-001 JWT secret hardening and startup enforcement.
2. SBP-002 bootstrap admin takeover prevention.
3. SBP-003 + SBP-004 abuse controls (public-target authorization and workload bounds).
4. SBP-005 login rate limiting.
5. SBP-006/SBP-007/SBP-008/SBP-009 production hardening and telemetry integrity.
