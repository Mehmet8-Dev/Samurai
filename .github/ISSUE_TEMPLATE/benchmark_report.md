---
name: Community Benchmark Report
about: Share independent Samurai benchmark results reproduced on your hardware
title: "[Benchmark] <CPU / NIC / GPU> — <1M TCP / L7 H2 / AF_XDP>"
labels: ["benchmark"]
---

## Hardware & Environment

- **CPU:** (e.g., AMD Ryzen 5 5600H / Intel Xeon Gold 6338 / Apple M3)
- **Logical Cores / RAM:**
- **NIC / GPU (if applicable):**
- **OS & Kernel:** (output of `uname -r`)
- **Compiler / Container:** (e.g., GCC 13 `-O3` or `ghcr.io/mehmet8-dev/samurai:latest`)

## Command Run

```bash
# Example:
./scripts/reproduce-benchmarks.sh --full
# or:
docker run --rm ghcr.io/mehmet8-dev/samurai:latest samurai_bench_1m_tcp
```

## Measured Output

<details>
<summary>Paste output or reports/reproduced_benchmark_summary.md</summary>

```text
Paste benchmark table / output here
```

</details>

## Observations & Bottlenecks Noted

- Any unexpected tail latency, RSS variance, or kernel tuning observations?
