# Product Guidelines: DDoSamurai v2.0

## Core Philosophy
*   **Modularity & Extensibility:** The `ddos_samurai` package structure (packet, senders, orchestrator, stealth, utils) must be preserved. New attack vectors should be pluggable.
*   **Performance First:** Critical paths (hot-paths) must optimize for speed. Use C extensions (`fast_sender`) or GPU kernels (CUDA/Numba) where Python is too slow. Avoid unnecessary object creation and memory copying (Zero-Copy).
*   **Async & Non-Blocking:** All network I/O should leverage `asyncio` and `uvloop`. Blocking operations must be offloaded or avoided.
*   **Type Safety & Readability:** Code should use Type Hinting where beneficial and adhere to PEP 8 standards for readability.
*   **Ethics & Safety:** Mandatory confirmation flags (`--confirm`) and ethical warnings must be present to prevent misuse.

## Visual Identity & UX
*   **CLI First:** The interface is strictly command-line based, powered by `argparse`. It must be scriptable and intuitive.
*   **"Samurai" Aesthetic:** Use a Consistent "Cyber-Samurai" theme (Red, White, Dark Grey/Black) for banners, logs, and animations (e.g., 3D startup cube).
*   **Rich UI:** Utilize the `rich` library for all user-facing output (tables, panels, progress bars).
*   **Minimalist Monitoring:** During attacks, avoid log spam. Display a clean, live-updating status panel showing real-time metrics (PPS, active workers).

## Error Handling & Logging
*   **Graceful Shutdown:** Handle `KeyboardInterrupt` (CTRL+C) robustly. Ensure all child processes, sockets, and GPU contexts are cleaned up properly.
*   **Tiered Logging:**
    *   **User:** INFO/WARNING logs to console (styled).
    *   **Developer:** DEBUG/TRACE logs and full stack traces to file (`ddos_logs.txt`).
    *   **Critical:** Alert user immediately for fatal errors (e.g., PermissionError, Missing Dependencies).
*   **Specific Exceptions:** Catch specific exceptions (e.g., `ImportError` for optional libs) rather than bare `Exception`. Provide actionable remediation hints (e.g., "Install cupy for GPU support").

## Development & Testing
*   **Safe Testing:** Developers must use local test environments (e.g., `python3 -m http.server`, local VMs). Unauthorized external testing is strictly prohibited.
*   **Hybrid Compatibility:** Code must support both CPU and GPU execution paths. If GPU libraries (`cupy`, `numba`) are missing or hardware is unavailable, the system must gracefully fallback to CPU mode.
*   **Lazy Imports:** Optional heavy dependencies (CuPy, Playwright) must be imported lazily (inside functions or try/except blocks) to keep the tool lightweight for basic use cases.

## Documentation & Versioning
*   **Semantic Versioning:** Follow `vX.Y.Z` versioning. Major versions imply significant architectural changes or new features.
*   **Code Documentation:** Complex logic, especially C extensions and GPU kernels, must have clear docstrings explaining inputs, outputs, and memory management strategy.
*   **Comprehensive README:** Major releases must be accompanied by an updated `README.md` covering installation, usage (CPU vs GPU), and examples.
