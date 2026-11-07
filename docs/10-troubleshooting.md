# 10 - Troubleshooting & Operational Diagnostics

This guide covers common diagnostic procedures, error symptoms, and resolution steps for the native C++ Samurai runtime.

---

## 1. ZMQ IPC Socket Permissions (`/tmp/samurai_jobs_*`)

- **Symptom:** `jobs socket init failed` or `Permission denied` on job startup.
- **Root Cause:** Stale socket files residing in `/tmp` from an earlier test run owned by a different user/UID.
- **Remediation:** Remove stale socket files and verify permissions:
  ```bash
  rm -f /tmp/samurai_jobs_* /tmp/samurai_events_*
  ```

---

## 2. Kernel-Bypass & AF_XDP Permissions (`Operation not permitted`)

- **Symptom:** `samurai_afxdp_worker` or raw socket initialization fails.
- **Root Cause:** Creating raw sockets and XDP XSK bindings requires `CAP_NET_RAW` and `CAP_NET_ADMIN` privileges.
- **Remediation:** Execute via `sudo` or grant persistent Linux capabilities to the compiled binary:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./build/ddos_samurai/zmq/daemon/samurai_afxdp_worker
  ```

---

## 3. Distributed Slave Fails to Connect to Master

- **Symptom:** `registration with master failed (endpoints=...)` in slave logs.
- **Verification Checklist:**
  1. Confirm `samurai_master` is running and listening on port `5099`:
     ```bash
     ss -tulpn | grep 5099
     ```
  2. Verify that `--cluster-secret` matches identically on both Master and Slave nodes.
  3. Verify that host firewalls (`iptables`, `nftables`, `ufw`) permit traffic on TCP port `5099`.
  4. If CurveZMQ is enabled, verify matching public/private key pairs.

---

## 4. Build System & Missing Compiler Dependencies

- **Symptom:** CMake reports `libzmq not found` or `OpenSSL not found`.
- **Remediation:** Install essential development libraries on Ubuntu/Debian:
  ```bash
  sudo apt-get update && sudo apt-get install -y \
    libzmq3-dev libssl-dev libbpf-dev libelf-dev \
    pkg-config build-essential cmake
  ```
