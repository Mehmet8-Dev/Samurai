# 08 - Configuration & Test Profile Management

The Samurai CLI and background daemons are configured via command-line arguments, JSON test profiles, and standard environment variables.

---

## 1. Test Profiles (`profiles.cpp`)

Common test configurations and benchmarks can be executed via pre-compiled profiles:

```bash
# List all built-in and discovered profiles
./build/samurai/cli/samurai --list-profiles

# Run a specific benchmark profile
./build/samurai/cli/samurai --profile dedicated_lab --confirm
```

---

## 2. Environment Variables Reference

| Variable Name | Default | Description |
|:---|:---|:---|
| `SAMURAI_CLUSTER_SECRET` | None | Shared cluster authentication key between Master and Slave nodes. |
| `SAMURAI_JWT_SECRET` | None | Secret key used for HMAC-SHA256 JWT tokens on the Management REST API. |
| `SAMURAI_XDP_INTERFACE` | None | Target network interface for AF_XDP kernel-bypass (e.g. `eth0`, `ens1f0`). |
| `SAMURAI_XDP_QUEUE_ID` | `0` | Physical hardware queue index to bind. |
| `SAMURAI_L7_TRANSPORT` | `kernel_socket` | Transport backend for L7 emulation (`kernel_socket`, `custom_tcp`, `custom_quic`). |
| `SAMURAI_TENANT_NAMESPACE` | `default` | Multi-tenant namespace boundary for resource isolation. |
