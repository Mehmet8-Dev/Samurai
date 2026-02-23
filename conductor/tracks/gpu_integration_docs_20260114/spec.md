# Specification: GPU Integration Tests, Dependency Optimization & Documentation

## 1. Overview
This track focuses on solidifying the core high-performance components of DDoSamurai v2.0 without altering the main logic. The goal is to ensure that the GPU (CUDA) and C (`fast_sender`) extensions are robustly tested, dependencies are managed efficiently (lazy loading), and documentation reflects the current state of the project.

## 2. Goals
1.  **Verify High-Performance Modules:** Create and run integration tests for `fast_sender` (C extension) and `gpu_packet.py` (CUDA kernels).
2.  **Optimize Dependencies:** Review `requirements.txt` and ensure optional libraries (like `cupy`, `playwright`) are handled with lazy imports to allow the tool to run in "light" mode on non-GPU systems.
3.  **Update Documentation:** Synchronize `README.md` with the current feature set, including installation instructions for both standard and high-performance modes.

## 3. Scope
### In-Scope
*   Creating test scripts in `tests/` for `fast_sender` and GPU modules.
*   Modifying source files to implement lazy import patterns where missing.
*   Updating `requirements.txt` and `README.md`.
*   Writing phase summary reports in markdown.

### Out-of-Scope
*   Refactoring the core orchestration logic (unless necessary for lazy imports).
*   Adding new attack vectors.
*   Full codebase style audit (PEP 8 enforcement) - deferred to a later track.

## 4. Success Criteria
*   **Tests:** A new test suite exists that verifies `fast_sender` compiles/runs and GPU kernels execute without errors (when hardware is present).
*   **Dependencies:** The tool runs on a clean environment (without `cupy`) without crashing immediately (graceful degradation).
*   **Documentation:** `README.md` accurately describes how to install and run the tool in both CPU-only and GPU-accelerated modes.
