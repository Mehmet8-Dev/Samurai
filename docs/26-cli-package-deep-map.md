# 26 - Native CLI Architecture Deep Map (`ddos_samurai/cli/`)

This document describes the internal architecture, module breakdown, and execution sequence of the native C++ `samurai` command-line front-end.

---

## 1. Module Breakdown

| C++ Source File | Architectural Responsibility |
| :--- | :--- |
| **`main.cpp`** | CLI entrypoint. Orchestrates argument parsing, profile resolution, validation, and supervisor job invocation. |
| **`args.cpp` / `args.hpp`** | POSIX-compliant argument parsing (`--worker`, `--target`, `--port`, `--count`, etc.). |
| **`validation.cpp` / `validation.hpp`** | Target allowlist verification, socket safety pre-checks, and parameter boundary assertions. |
| **`profiles.cpp` / `profiles.hpp`** | Maps named benchmark profiles (`dev`, `ci_safe`, `dedicated_lab`) to internal operational configurations. |
| **`kpi_gate.cpp` / `kpi_gate.hpp`** | Compares post-execution metrics (RPS, loss ratio, latency percentiles) against strict quality gates. |
| **`reporting.cpp` / `reporting.hpp`** | Formats run results into structured JSON artifacts, Markdown tables, or terminal summaries. |
| **`rfc_suite.cpp` / `rfc_suite.hpp`** | Implements automated RFC positive and negative conformance testing suites. |
| **`../orchestrator/supervisor.cpp`** | Spawns worker processes via `fork()` / `execvp()`, establishing private Unix IPC channels (`ipc:///tmp/samurai_jobs_*`). |

---

## 2. CLI Execution Lifecycle

![Samurai CLI Execution & Worker Lifecycle](assets/diagrams/samurai_cli_lifecycle.svg)

<details>
<summary>Lifecycle Sequence Diagram</summary>

```mermaid
sequenceDiagram
    participant User as Operator / Automated CI
    participant Main as CLI (main.cpp)
    participant Args as args.cpp / validation.cpp
    participant Sup as supervisor.cpp
    participant Worker as samurai_*_worker

    User->>Main: ./samurai --worker afxdp --target 10.0.0.50 --count 100000 --confirm
    Main->>Args: ParseArgs() & Validate()
    Main->>Sup: RunJob(SupervisorConfig, JobOptions)
    Sup->>Worker: fork() + execvp(samurai_afxdp_worker)
    Sup->>Worker: START_JOB (ZMQ IPC)
    Worker-->>Sup: HEARTBEAT / METRICS
    Worker-->>Sup: JOB_DONE
    Sup-->>Main: Execution Summary
    Main->>User: JSON / Terminal Summary
```

</details>
