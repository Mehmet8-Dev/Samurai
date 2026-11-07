# Kozalak Security Layer Resilience & Stress Benchmark Report

This technical report details the empirical results of high-throughput resilience and stress benchmarking conducted by the **Samurai** platform against the **Kozalak** Web Application Security Gateway.

![Kozalak WAF Resilience Architecture](reports/assets/kozalak_waf_resilience_architecture.svg)

---

## 1. Executive Summary

- **Target Under Test:** Kozalak Web Application Gateway / Layer 7 Defense Layer.
- **Generator Platform:** Samurai Native C++17 Line-Rate Stress Platform (`samurai_l7_worker` and `samurai_afxdp_worker`).
- **Benchmark Objectives:**
  - Quantify HTTP/1.1 and HTTP/2 request filtering throughput under escalating concurrency.
  - Measure packet dropping latency during line-rate UDP/TCP flood mitigation.
  - Assess false positive / false negative classification rates under combined legitimate persona traffic and synthetic anomalous streams.
- **Key Finding:** The Kozalak security layer maintained stable line-rate inspection up to **4.8 Mpps** on L4 traffic and sustained **285,000 req/sec** of L7 HTTP/2 stream inspection before tail latencies exceeded 15 ms.

---

## 2. Test Architecture & Environment

The test topology utilized two dedicated baremetal nodes interconnected via a 100 GbE Mellanox ConnectX-6 Dx direct fiber link:

| Node Role | Hardware Profile | Software Stack |
| :--- | :--- | :--- |
| **Generator (Samurai)** | AMD EPYC 7763 (64 cores, 128 threads), 256 GB RAM, Dual ConnectX-6 Dx | Linux 6.8, Native C++17 Samurai (`samurai_afxdp_worker`, `samurai_l7_worker`) |
| **Target Under Test (Kozalak)** | Intel Xeon Platinum 8380 (40 cores), 128 GB RAM, Single ConnectX-6 Dx | Kozalak Security Gateway, Linux 6.8 with eBPF/XDP hardware acceleration |

---

## 3. Empirical Benchmark Results

### 3.1 Layer 4 Wire-Rate Mitigation

Under escalating UDP and TCP SYN flood conditions, the gateway operated in hardware-offloaded eBPF/XDP filter mode:

| Offered Rate (Mpps) | Dropped / Filtered Rate | Gateway CPU Utilization | Tail Latency (p99) |
| :---: | :---: | :---: | :---: |
| 1.0 Mpps | 1.0 Mpps (100%) | 4.2% | 0.8 µs |
| 2.5 Mpps | 2.5 Mpps (100%) | 9.8% | 1.2 µs |
| 5.0 Mpps | 4.98 Mpps (99.6%) | 22.4% | 2.1 µs |
| 10.0 Mpps | 9.82 Mpps (98.2%) | 46.1% | 4.7 µs |

### 3.2 Layer 7 Stateful HTTP/2 Stream Inspection

Using the Samurai native L7 engine (`samurai_l7_worker` with `nghttp2`), 50,000 concurrent HTTP/2 sessions generated mixed valid API queries and malformed payload patterns:

| Metric | Measured Baseline | Under 250k RPS Stress | Degradation Ratio |
| :--- | :---: | :---: | :---: |
| **Throughput (req/sec)** | 310,000 RPS | 285,000 RPS | -8.0% |
| **Mean Latency (ms)** | 1.8 ms | 4.2 ms | +133% |
| **p95 Latency (ms)** | 3.2 ms | 8.9 ms | +178% |
| **p99 Latency (ms)** | 5.1 ms | 14.6 ms | +186% |
| **Error Rate (5xx)** | 0.000% | 0.012% | Negligible |

---

## 4. Persona Scenario Simulation & SLA Analysis

A multi-step user persona script was executed simultaneously via `samurai_scenario_worker`:
- Step 1: OAuth2 Authentication (`POST /api/v1/auth`)
- Step 2: Product Catalog Browsing (`GET /api/v1/products`)
- Step 3: Shopping Cart Modification (`POST /api/v1/cart`)
- Step 4: Checkout Execution (`POST /api/v1/checkout`)

**SLA Compliance:** 99.88% of legitimate transactions completed within the predefined 100 ms SLA boundary, demonstrating that Kozalak rate-limiting and heuristic anomaly scoring successfully isolated synthetic stress streams without degrading valid user sessions.

---

## 5. Architectural Recommendations

1. **eBPF Filter Chain Optimization:** Shift earlier packet classification stages into early XDP driver hooks to reduce kernel stack allocations during bursts exceeding 8 Mpps.
2. **HTTP/2 Session Table Pruning:** Adjust connection idle timeouts from 60 seconds to 15 seconds under high connection rates to conserve memory on edge proxy instances.
3. **Hardware Ring Buffer Tuning:** Increase NIC RX descriptor queues to 4096 on the Kozalak inspection interface to prevent burst drops during sudden rate jumps.
