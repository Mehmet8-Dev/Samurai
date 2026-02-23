# Tech Stack: DDoSamurai v2.0

## Programming Languages
*   **Python:** The core language for orchestration, CLI, logic, and general application flow.
*   **C:** Used for high-performance extensions (`fast_sender`) to handle packet transmission efficiently.
*   **CUDA (Numba/CuPy):** Used for massive parallel packet generation and manipulation on NVIDIA GPUs.

## Network & Transport
*   **Scapy:** Primary library for packet crafting and manipulation.
*   **Raw Sockets:** Low-level socket access (`AF_PACKET` v2/v3, `AF_INET`) for maximum throughput.
    *   **AF_PACKET v3:** Leveraged for high-performance, zero-copy packet transmission on Linux.
*   **Asyncio & uvloop:** Provides the high-performance asynchronous event loop for concurrent operations.

## Web & Application Layer
*   **Httpx:** A fully featured HTTP client library with HTTP/2 support.
*   **Playwright:** Used for "Ninja Mode" to simulate real browser interactions and bypass advanced WAF protections (Cloudflare, etc.).
*   **FastAPI:** Powers the real-time metrics server.

## GPU & Acceleration
*   **CuPy:** NVIDIA CUDA-accelerated array library, used for GPU-based buffer operations.
*   **Numba:** JIT compiler for generating high-performance CUDA kernels from Python code.

## CLI & User Interface
*   **Rich:** Library for creating beautiful, terminal-based user interfaces (panels, tables, live updates).
*   **Argparse:** Standard library for parsing command-line arguments.

## Testing
*   **Pytest:** Framework for writing and executing unit and integration tests.

## Infrastructure
*   **Operating System:** Linux (Strongly Recommended for full feature set like `sendmmsg` and `AF_PACKET`). Windows has partial support.
*   **Hardware:** NVIDIA GPU (Optional but required for high-performance modes).
