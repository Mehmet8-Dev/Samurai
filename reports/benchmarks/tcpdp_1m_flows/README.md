# DDoSamurai tcpdp 1,000,000 (1M) Active TCP Flows Benchmark Report

- **Date:** 2026-10-17 14:57:53 UTC
- **Status:** **PASSED**
- **Test Target:** 1,000,000 Active Established TCP Flows (Single-Core, 6 Physical Cores & 12 SMT Workers, 5 Iterations/Mode)

## 1. Executive Summary & Key Performance Indicators (KPIs)

| Metric | Measured Value | Unit / Target | Verification Status |
| :--- | :--- | :--- | :--- |
| **Total Active Flows ($N$)** | 1,000,000 | flows | **PASS** (100% Allocated) |
| **Compile-Time `sizeof(FlowEntry)`** | 336 | bytes (raw C++ struct size) | **PASS** |
| **SYN Frames Emitted & Drained** | 1,000,000 | frames (62.94 MB wire) | **PASS** (0% TX Ring Drop) |
| **Phase 2 SYN Enqueue Rate** | 1,178,130.00 | Conn/sec (1,178.13 kCPS) | **PASS** (848.80 ms) |
| **64-Shard Hash Variance** | 0.0320% | <= 5.0000% | **PASS** (Optimal Uniformity) |
| **Shard Distribution (Min / Max)** | 15620 / 15630 | Mean: 15625 flows/shard | **PASS** (StdDev: 2.94) |
| **Full 3-Way Handshakes Completed** | 1,000,000 | / 1,000,000 (`kEstablished`) | **PASS** (100.0% Established) |
| **ACK Frames Emitted & Drained** | 1,000,000 | frames (51.50 MB wire) | **PASS** (0% TX Ring Drop) |
| **Phase 4 Handshake Rate** | 1,920,330.00 | handshakes/sec (520.74 ms) | **PASS** |
| **Baseline Process VmRSS** | 4.02 | MB | **PASS** |
| **Established 1M Flows VmRSS** | 581.29 | MB (Peak VmHWM: 581.29 MB) | **PASS** (< 2.0 GB ceiling) |
| **Process RSS Delta / Flow (`ESTABLISHED`)** | 605.31 | bytes/flow (FlowEntry + map node + deque + 4-tuple index + timers) | **PASS** |
| **Post-Reclaim VmRSS (`malloc_trim`)** | 5.66 | MB (74.54 ms teardown) | **PASS** (Zero Memory Leak) |
| **Lockless Lookups Throughput** | 66.85 | Million lookups/sec (44.87 ms) | **PASS** (12 threads, 3M hits) |
| **Controlled Single-Core (1W) Median** | 991,912.00 | CPS (1008.15 ms, 2.98 M-PPS) | **PASS** |
| **Controlled Physical Cores (6W) Median** | 2,651,640.00 | CPS (377.13 ms, 7.95 M-PPS) | **PASS** (2.67x speedup) |
| **Controlled Full SMT (12W) Median** | 2,678,510.00 | CPS (373.34 ms, 8.04 M-PPS) | **PASS** (2.70x speedup) |
| **Controlled SMT + RFC 1071 Checksum** | 2,705,970.00 | CPS (369.55 ms, 8.12 M-PPS) | **PASS** (-1.01% delta) |
