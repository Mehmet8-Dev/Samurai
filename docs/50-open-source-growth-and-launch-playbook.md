# 50 - Open-Source Growth & Viral Launch Playbook (Samurai v3.3.1)

This playbook translates the proven open-source viral distribution mechanics behind breakthrough developer repositories (such as REA's outcome-first positioning, 1-command onboarding, MCP agent integration, visual proof, and segmented multi-community engineering launches) into a concrete execution plan for **Samurai (`Mehmet8-Dev/Samurai`)**.

---

## 1. GitHub Repository Metadata & Storefront Checklist

Before publishing any external post, configure these in **GitHub → Settings**:

- **Short Description (under 160 chars):**
  > `Pure C++17 line-rate network resilience & stress platform — 1M stateful TCP flows in 577 MiB (605 B/flow), AF_XDP/DPDK, GeForce BAR1 P2P CUDA, 5G CUPS & MCP.`
- **Website / Homepage URL:** Link to your landing page or `https://github.com/Mehmet8-Dev/Samurai#readme`
- **GitHub Topics (copy-paste all 20):**
  `cpp17`, `networking`, `load-testing`, `stress-testing`, `tcp`, `af-xdp`, `dpdk`, `cuda`, `gpu-networking`, `http2`, `http3`, `quic`, `io-uring`, `telecom`, `5g`, `zeromq`, `benchmark`, `mcp`, `kernel-bypass`, `network-security`
- **Social Preview Image (1280×640):**
  Export a 1280×640 PNG banner (for example from [`docs/assets/diagrams/samurai_system_architecture.svg`](assets/diagrams/samurai_system_architecture.svg) or your video stills) and upload it under **Settings → Social preview**.
- **GitHub Discussions Categories to Enable:**
  - `Benchmarks & Hardware Results` (Pin a thread: *"Community 1M TCP Flow Leaderboard — run `docker run --rm ghcr.io/mehmet8-dev/samurai:latest samurai_bench_1m_tcp` and post your CPU!"*)
  - `Architecture & RFCs`
  - `Show & Tell` (Lab topologies, WAF/BNG/5G UPF test setups)
- **Publish a `v3.3.1` Tag After Pushing:**
  Pushing a `v3.3.1` tag triggers `.github/workflows/release.yml`, automatically rebuilding `ghcr.io/mehmet8-dev/samurai:latest` so it includes:
  - Auto-discovered worker binaries (no `--worker-dir` required)
  - Native C++17 `samurai_mcp` (22 tools, 5 skill resources, 5 workflow prompts) + `/usr/local/share/samurai/skills`
  - Built-in `samurai_bench_1m_tcp`, `samurai_bench_100k_tcp`, and `samurai_bench_l7` commands inside the GHCR image!

---

## 2. Six Standalone Community Engineering Posts (Copy-Paste Ready)

> **Rule #1 of technical virality:** Never post the same generic feature list everywhere. Split Samurai into **6 distinct, verifiable engineering stories** tailored to each community's obsession.

### Story 1 — Hacker News (`Show HN`)
- **Title:** `Show HN: Samurai – 1M stateful TCP flows in 577 MiB RAM (605 B/flow) in C++17`
- **URL:** `https://github.com/Mehmet8-Dev/Samurai`
- **First Comment (post immediately after submitting):**
  > Hi HN, I'm the author of Samurai (`AGPL-3.0`, pure C++17).
  >
  > I built Samurai because I kept hitting a gap between scripting load testers (which bottleneck on GC/syscalls) and raw stateless packet blasters (which can't do stateful TCP SACK recovery, HTTP/2/QUIC state machines, or 5G carrier signaling).
  >
  > The engineering detail I'm most proud of is our 64-shard userspace TCP dataplane (`TcpDataplaneCore`): initially 1,000,000 concurrent flows consumed 1,572 MiB (`1,648 B/flow`) despite `sizeof(FlowEntry) == 416 B`. Profiling showed `libstdc++`'s `std::deque` retains 512-byte heap slabs even after `clear()`, plus red-black tree nodes in `std::map` for out-of-order reassembly. Replacing those with flat `std::vector` + capacity reclaim on `ESTABLISHED`, inline 24-byte TCP options, and cache-line-aligned 64-shard lock striping cut memory by **63.3% down to `605.31 B/flow` (`577 MiB` for 1M flows)**.
  >
  > To be completely transparent about measurement boundaries:
  > - **In-memory dataplane (1M full 3-way handshakes + RFC 1071 checksums):** `2.71M CPS` / `8.13 Mpps` on a 6-core Ryzen 5 5600H laptop.
  > - **Real Linux kernel wire (`netns + veth + AF_PACKET` vs kernel `accept4()`):** `133.5k CPS` across 100k handshakes with 0 retransmits.
  > - **L7 Shared-Nothing (`nghttp2`):** `189.9k RPS` across 1M HTTP/2 flows (`P99 4ms`).
  >
  > You can reproduce the 1M TCP flow benchmark locally in ~10 seconds without compiling:
  > `docker run --rm ghcr.io/mehmet8-dev/samurai:latest samurai_bench_1m_tcp`
  >
  > It also ships a zero-dependency MCP server so Claude Code / Cursor can run safety-gated (loopback/RFC1918-only) benchmarks, plus optional `AF_XDP`, `DPDK`, consumer GeForce BAR1 P2P CUDA, and 4G/5G telecom workers. Happy to answer deep-dive questions on the TCP state machine, `io_uring`/kTLS, or CUDA P2P!

### Story 2 — `r/cpp` (Deep C++17 Memory Layout & Lock Striping)
- **Title:** `How replacing std::deque + std::map cut per-flow RAM by 63.3% (1,648 B → 605 B/flow) across 1,000,000 concurrent TCP flows in C++17`
- **Angle:** Show the exact `sizeof(FlowEntry)` vs `VmRSS` mystery, the 5 C++ optimizations from [`docs/benchmarks/43-tcpdp-1m-flows-benchmark-report.md`](benchmarks/43-tcpdp-1m-flows-benchmark-report.md) (`std::deque` 512B slab retention, `ankerl::unordered_dense`, inline `std::array<uint8_t, 24>`, `PaddedMutex` 64-byte alignment), and invite C++ engineers to run `./scripts/reproduce-benchmarks.sh --full` and critique `samurai/l4/tcp_dataplane_core.hpp`.

### Story 3 — `r/linux` & `r/networking` (Kernel Wire Interop + `AF_XDP` + `io_uring`/kTLS)
- **Title:** `Testing a custom userspace TCP + HTTP/2/QUIC engine against the live Linux kernel (netns + veth + AF_PACKET, AF_XDP, io_uring/kTLS)`
- **Angle:** Highlight honest engineering — verifying a custom userspace TCP stack (`RFC 6675 SACK`) against real Linux `accept4()` in isolated `netns + veth` at `133.49 kCPS` with zero retransmits, plus comparing `AF_PACKET TPACKET_V3`, `AF_XDP` zero-copy UMEM, and `io_uring` vs `epoll` reactors.

### Story 4 — `r/CUDA` / NVIDIA Developer Forums (Consumer GeForce BAR1 P2P & QUIC Crypto)
- **Title:** `Open-source GeForce BAR1 P2P GPU-to-NIC DMA, GPU-initiated MMIO doorbells, and 129M masks/s CUDA QUIC crypto on a laptop GTX 1650`
- **Angle:** Most GPU networking examples require $10k+ datacenter GPUs + GPUDirect RDMA. Link [`docs/46-gpu-initiated-doorbell-and-baremetal-pmd.md`](46-gpu-initiated-doorbell-and-baremetal-pmd.md) and [`docs/47-zero-cpu-persistent-dataplane-architecture.md`](47-zero-cpu-persistent-dataplane-architecture.md) showing `cudaHostRegisterIoMemory` doorbell rings, persistent VRAM dataplane kernels, and RFC 9001 QUIC crypto batch offload (`129.3M` AES-ECB masks/s, `11.76M` HKDF keys/s, `738.9k PPS` AES-128-GCM on a GTX 1650 Mobile).

### Story 5 — Telecom / 5G Core Engineering (LinkedIn & Carrier Communities)
- **Title:** `Open-sourcing a C++17 4G/5G CUPS carrier traffic & signaling generator (GTP-U QFI, PFCP N4, SCTP multihoming, Diameter Ro/Gx, SIP/SRTP + DPU ARM Seqlock)`
- **Angle:** Highlight the massive cost of commercial carrier testers (Spirent/Keysight/Ixia) for BNG/CGNAT/UPF lab validation, and showcase Samurai's [`docs/49-telecom-gpu-dpu-cups-dataplane-architecture.md`](49-telecom-gpu-dpu-cups-dataplane-architecture.md) and RFC 2544/3511/8219 compliance runner.

### Story 6 — X / Twitter Launch Thread (5-Post Viral Format)
- **Post 1 (Hook + Visual/GIF):**
  > I just open-sourced **Samurai v3.3.1** — a pure C++17 network resilience & line-rate stress platform.
  >
  > One laptop (Ryzen 5 5600H + GTX 1650):
  > • 1,000,000 stateful TCP flows in 577 MiB RAM (`605 B/flow`, -63.3%)
  > • 2.71M CPS / 8.13 Mpps userspace handshakes
  > • 189.9k RPS stateful HTTP/2 (1M flows, 4ms P99)
  > • 129.3M QUIC header-protection masks/s on CUDA
  > • Built-in MCP server for Claude Code & Cursor
  >
  > Verify it in 10 seconds with 1 Docker command 👇
  > *(Attach 20-second terminal GIF of `samurai_bench_1m_tcp`)*
- **Post 2 (The C++ Memory Story):** `std::deque` 512B slab retention → `-63.3% RAM` (`1,648 B` → `605 B/flow`).
- **Post 3 (Consumer GPU BAR1 P2P):** Why datacenter-only GPU networking doesn't have to stay locked behind paywalls + persistent VRAM kernel diagram (`docs/assets/diagrams/samurai_gpu_p2p_dataplane.svg`).
- **Post 4 (Native C++17 MCP + RL Autopilot):** One-liner `claude mcp add samurai -- ./build/mcp/samurai_mcp` (or via GHCR Docker) — zero Python, native C++17 MCP `2024-11-05` server driving 1M TCP benchmarks AND Closed-Loop Mahoraga RL Autopilot with fail-closed loopback/RFC1918 safety.
- **Post 5 (CTA — Independent Verification):** "Don't trust my screenshots — run `docker run --rm ghcr.io/mehmet8-dev/samurai:latest samurai_bench_1m_tcp` on your CPU and reply with your CPS & B/flow! Repo (AGPL-3.0): https://github.com/Mehmet8-Dev/Samurai"

---

## 3. 2-Minute Demo Video & Terminal GIF Script

Visual proof is what turns casual scrollers into GitHub stars and testers. Record two short assets:

### Asset A — 20-Second Terminal GIF for README & X/Twitter
Record with `asciinema` + `agg`:
```bash
asciinema rec /tmp/samurai_demo.cast -c "bash -c '
  echo \"$ ./build/l4/test_100k_tcp_flows\"
  ./build/l4/test_100k_tcp_flows
  echo \"\"
  echo \"$ ./build/zmq/bench_l7_stateful_userspace --proto h2 --flows 10000\"
  ./build/zmq/bench_l7_stateful_userspace --proto h2 --flows 10000
  echo \"\"
  echo \"$ ./build/cli/samurai --run-rfc-suite all | head -n 22\"
  ./build/cli/samurai --run-rfc-suite all | head -n 22
'"
agg --font-size 16 --theme monokai /tmp/samurai_demo.cast docs/assets/samurai_demo.gif
```

### Asset B — 2-Minute YouTube / LinkedIn Technical Walkthrough
1. **0:00–0:20 (Hook):** Show `samurai_bench_1m_tcp` hitting 1M flows in 577 MiB (`605 B/flow`, `2.71M CPS`) live in terminal.
2. **0:20–0:50 (Why It's Fast):** Show 15 lines of `tcp_dataplane_core.hpp` (`std::deque` → flat `std::vector`, 64-shard `PaddedMutex`).
3. **0:50–1:25 (Distributed + Grafana):** Run `docker compose -f docker-compose.distributed.yml up -d`, curl `:8089/healthz`, show live metrics in `monitoring/` Grafana dashboard.
4. **1:25–1:50 (MCP + Claude Code):** Ask Claude Code to benchmark a local service via `samurai-mcp`, show structured JSON KPI pass/fail output and public-IP fail-closed block.
5. **1:50–2:00 (CTA):** Show the 1-line `docker run` command and invite viewers to post their CPU results on GitHub Discussions.

---

## 4. Sequenced 4-Week Rollout Calendar

Do **not** post to all channels on the same day. Space stories out so each wave drives a fresh burst of GitHub Trending visibility and independent benchmark verifications:

| Week | Primary Channel | Story / Hook | Goal |
| :--- | :--- | :--- | :--- |
| **Week 1 (Tue 15:00 UTC)** | GitHub `v3.3.1` release + **Show HN** + **X Thread** | 1M TCP flows in 577 MiB (`605 B/flow`) + 1-command Docker reproduction | Hit HN front page + GitHub Trending (C++) |
| **Week 2 (Wed)** | **`r/cpp`** + **Lobste.rs** | Deep dive: `std::deque` slab retention & cache-line lock striping (`-63.3% RAM`) | High-signal C++ code reviews & contributors |
| **Week 3 (Tue)** | **`r/CUDA`** + **NVIDIA Dev Forums** + YouTube Short | Consumer GeForce BAR1 P2P DMA + 129M masks/s QUIC CUDA crypto | Capture GPU/HPC developer wave |
| **Week 4 (Thu)** | **`r/networking`** + **`r/linux`** + **LinkedIn Telecom** | Kernel `netns+veth` interop (`133.5k CPS`) + 5G CUPS + MCP AI benchmarking demo | Enterprise/carrier visibility & commercial support leads |
