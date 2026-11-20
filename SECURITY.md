# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `3.0.x` | Yes |
| `< 3.0.0` | No |

---

## Coordinated Vulnerability Disclosure

If you discover a security vulnerability in Samurai (such as memory corruption in packet parsers, control-plane authentication/RBAC bypasses, ZMQ wire-protocol parsing flaws, or target-safety gate bypasses), please report it responsibly **without** opening a public GitHub Issue.

### How to Report

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Submit a confidential report via [GitHub Security Advisories](https://github.com/Mehmet8-Dev/Samurai/security/advisories/new).
2. **Direct Maintainer Contact:**  
   If you cannot use GitHub Security Advisories, open a minimal request on GitHub Discussions asking for a private contact channel without disclosing technical exploit details.

### What to Include
- Affected subsystem/file path (e.g., `samurai/l7_emu_native/`, `samurai/control/`, `samurai/telecom/`)
- Build configuration and environment details (OS, kernel version, CMake flags)
- Minimal proof-of-concept or reproduction steps on an isolated loopback/lab target
- Impact assessment and suggested remediation (if available)

We aim to acknowledge reports within **72 hours** and provide an initial triage assessment within **7 days**. Please refrain from testing vulnerabilities against any infrastructure you do not own or hold explicit written authorization to assess.

---

## Secure-by-Default Architecture

Samurai is designed for authorized lab, carrier-validation, and resilience testing with defensive guardrails enforced by default:

1. **Target Safety Gate (`samurai/core/target_safety.cpp`):**
   - By default, `samurai` and `samurai_master` only permit traffic toward **private (RFC 1918 / RFC 6598) and loopback** addresses.
   - Public IP targets are rejected unless explicitly authorized via `--allow-public-target` or `--allow-target <IP|CIDR>`.
   - `--deny-target <IP|CIDR>` always takes highest precedence over any allowlist.
2. **Control-Plane Authentication, Transport Encryption & Auditability:**
   - Distributed ZMQ RPC supports **CURVE** mutual encryption (`samurai_master --gen-curve-keys`).
   - The HTTP REST Management API (`:8089`) supports **HMAC-SHA256 JWT** authentication and **Role-Based Access Control (RBAC)**.
   - Administrative and RBAC events are recorded in an **append-only SHA-256 hash-chained audit log** (`tools/verify_audit_chain.py`).
3. **Secret Hygiene:**
   - Cluster secrets and API tokens (`SAMURAI_CLUSTER_SECRET`, `SAMURAI_MANAGEMENT_API_*`) should always be supplied via environment variables or mounted Kubernetes secrets—never via command-line flags or committed files.
4. **Compiler & Container Hardening:**
   - Native binaries are compiled with `-fvisibility=hidden`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, and `-Wl,-z,relro,-z,now` (`samurai/CMakeLists.txt`).
   - Production containers run as non-root UID/GID `10001:10001` under `tini` (`Dockerfile`).
5. **Automated Repository Hygiene:**
   - Dependabot (`.github/dependabot.yml`), secret scanning (`.github/workflows/security.yml`), and static analysis guard incoming PRs and dependencies.
