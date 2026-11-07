# 07 - Target Safety & RFC Compliance Verification

Samurai enforces strict safety boundaries (`ddos_samurai/core/target_safety.cpp` and `ddos_samurai/cli/validation.cpp`) to prevent accidental transmission to unauthorized subnets or critical public infrastructure.

---

## 1. Safety Boundary Enforcement

- **Default Private Allowlist:**
  By default, test execution is restricted strictly to loopback (`127.0.0.0/8`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and configured lab IP blocks.
- **Explicit Public Destination Flag:**
  Transmitting packets to routable Internet IP addresses strictly requires the `--allow-public-target` parameter along with interactive or command-line confirmation (`--confirm`).
- **Global Inviolable Denylist:**
  Critical public infrastructure ranges (e.g. root DNS nameservers, government/emergency IP blocks, loopback broadcast) and subnets configured via `--safety-global-deny-target` can never be targeted under any condition, overriding any allowlist configuration.

---

## 2. Safety Command Flags

```bash
# Allow tests only against an explicitly defined lab subnet
./build/ddos_samurai/cli/samurai --allow-target 192.168.10.0/24 ...

# Explicitly ban a production management subnet
./build/ddos_samurai/cli/samurai --safety-global-deny-target 10.0.0.0/24 ...

# Authorized public target testing
./build/ddos_samurai/cli/samurai --allow-public-target --target 203.0.113.10 ...
```

---

## 3. RFC Compliance Validation (`rfc_suite.cpp`)

To verify the mathematical and structural correctness of synthesized packet headers, operators can run built-in RFC validation suites:

```bash
# Verify compliant RFC packet structures
./build/ddos_samurai/cli/samurai --rfc-suite positive

# Verify packet filters and anomaly rejection
./build/ddos_samurai/cli/samurai --rfc-suite negative
```
