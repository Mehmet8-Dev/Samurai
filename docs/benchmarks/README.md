# Samurai Benchmarks & Ecosystem Comparison

All measurements below were captured on a commodity laptop (AMD Ryzen 5 5600H — 6 physical cores / 12 SMT threads, 13 GiB RAM, GTX 1650 Mobile, Linux `6.14`, GCC 13 `-O3 -mavx2`), with explicit separation between in-memory dataplane, Linux kernel wire (`netns + veth`), and GPU offload boundaries.

---

## Verified Empirical Results

| Benchmark | Boundary / Scope | Measured Result | Full Report |
| :--- | :--- | :--- | :--- |
| **1M Active TCP Flows RAM** | Userspace `TcpDataplaneCore` (`VmRSS`) | `605.31 B/flow` (`577.3 MiB` total — 63.3% reduction from `1,648 B/flow`) | [43 - L4 1M Flows Report](43-tcpdp-1m-flows-benchmark-report.md) |
| **1M TCP 3-Way Handshakes** | In-memory 64-shard dataplane + RFC 1071 checksums | `2.71M CPS` / `8.13 Mpps` (`369 ms` for 1M handshakes, 12 SMT) | [43 - L4 1M Flows Report](43-tcpdp-1m-flows-benchmark-report.md) |
| **Kernel Wire Interop** | Isolated `netns + veth + AF_PACKET` vs Linux `accept4()` | `133.49 kCPS` / `400.48 kPPS` (100,000 handshakes, 0 retransmits) | [43 - L4 1M Flows Report](43-tcpdp-1m-flows-benchmark-report.md) |
| **1M Stateful HTTP/1.1 Flows** | Shared-nothing userspace TCP + dynamic RFC 7230 | `182.5k RPS` (100.0% success, P50 `3 ms`, P99 `15 ms`) | [44 - L7 Stateful Report](44-l7-stateful-userspace-benchmark-report.md) |
| **1M Stateful HTTP/2 Flows** | Shared-nothing userspace TCP + `nghttp2` | `189.9k RPS` (100.0% success, P50 `2 ms`, P99 `4 ms`, 4 shards) | [44 - L7 Stateful Report](44-l7-stateful-userspace-benchmark-report.md) |
| **100k Stateful HTTP/3 QUIC** | Real UDP sockets + `ngtcp2`/`nghttp3` + TLS 1.3 + coalescing | `7,905 RPS` (P50 `2.81 ms`, P99 `7.32 ms`, 11–12x datagram coalescing) | [44 - L7 Stateful Report](44-l7-stateful-userspace-benchmark-report.md) |
| **QUIC RFC 9001 CUDA Crypto** | GPU batch HKDF + AES-ECB Header Protection + AEAD | `129.3M masks/s`, `11.76M HKDF keys/s`, `738.9k PPS` AES-GCM (GTX 1650) | [44 - L7 Stateful Report](44-l7-stateful-userspace-benchmark-report.md) |

---

## Capability Comparison

| Capability | **Samurai v3.3** | `wrk` / `hey` | `k6` / `Locust` | `Cisco TRex` | `pktgen` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Pure Native C++17 (Zero Scripting Runtime) | Yes | C / Go | JS / Python | C++ / Py ctrl | Kernel C |
| Stateful Userspace TCP (1M Flows @ 605 B/flow) | Yes | No | No | Yes | No |
| Stateful HTTP/1.1, HTTP/2 (`kTLS`), QUIC/HTTP-3 | Yes | H1 only | H1/H2 (k6) | Partial | No |
| `AF_XDP` & `DPDK` Kernel-Bypass | Yes | No | No | DPDK | Kernel TX |
| Consumer GeForce GPU BAR1 P2P + CUDA Crypto | Yes | No | No | No | No |
| 4G/5G Carrier Telecom (`GTP-U`, `PFCP`, `SCTP`, `Diameter`, `SIP`) | Yes | No | No | Partial | No |
| Distributed ZMQ Master/Slave + Closed-Loop RL Autopilot | Yes | No | Cloud / Basic | No | No |
| Fail-Closed Target Safety Gate + Native C++17 MCP Server | Yes | No | No | No | No |

---

## Reproduce Locally

```bash
# GHCR source-runtime container (contains uncompiled source+toolchain; compiles locally with SAMURAI_NATIVE_ARCH=ON on first run)
docker run --rm -v samurai-build-cache:/var/cache/samurai ghcr.io/mehmet8-dev/samurai:latest samurai_bench_1m_tcp
docker run --rm -v samurai-build-cache:/var/cache/samurai ghcr.io/mehmet8-dev/samurai:latest samurai_bench_l7 --proto h2 --flows 10000

# Or local host-native build inside Docker (`SAMURAI_NATIVE_ARCH=ON`)
docker build -t samurai:local .
docker run --rm samurai:local samurai_bench_1m_tcp

# Or via 1-command npx launcher & automated hardware report (writes reports/reproduced_benchmark_summary.md)
npx -y samurai-net bench 1m-tcp
./scripts/reproduce-benchmarks.sh          # Quick (~5s): 100k TCP + 10k L7 H1/H2 + RFC suite
./scripts/reproduce-benchmarks.sh --full   # Full (~45s): includes 1,000,000 active TCP flows
```

Independent hardware results can be shared in [GitHub Discussions](https://github.com/Mehmet8-Dev/Samurai/discussions) or submitted using the [Benchmark Report template](../../.github/ISSUE_TEMPLATE/benchmark_report.md).
