# Plan: GPU Integration Tests, Dependency Optimization & Documentation

## Phase 1: Integration Testing (GPU & C Extensions)
- [x] Task: Create a test harness for `fast_sender` (C extension).
    - *Sub-task:* Write a Python script `tests/test_fast_sender.py` to import the module and call basic functions (`send_optimized`, `setup_xdp_socket` mock).
    - *Sub-task:* Verify successful compilation and linkage during test execution.
- [x] Task: Create a test harness for GPU modules (`gpu_packet.py`, `gpu_payload.py`).
    - *Sub-task:* Write `tests/test_gpu_modules.py` that mocks `cupy`/`numba` (if hardware missing) or runs a basic kernel (if hardware present).
    - *Sub-task:* Ensure tests handle `ImportError` gracefully if GPU libs are missing.
- [x] Task: Conductor - User Manual Verification 'Phase 1: Integration Testing' (Protocol in workflow.md)

## Phase 2: Dependency Optimization (Lazy Imports)
- [x] Task: Fix missing dependencies in `requirements.txt` and report.
    - *Sub-task:* Analyzed imports and updated `requirements.txt`.
    - *Sub-task:* Generated `reports/dependency_update.md`.
- [x] Task: Conductor - User Manual Verification 'Phase 2: Dependency Optimization' (Protocol in workflow.md)

## Phase 3: Documentation Update
- [x] Task: Update `README.md`.
    - *Sub-task:* Add a clear "Installation" section distinguishing between "Standard (CPU)" and "Pro (GPU/Ninja)" installation.
    - *Sub-task:* Document the new test scripts and how to run them.
    - *Sub-task:* Add the "Legal Warning" and "Features" summary based on the Product Guide.
- [x] Task: Conductor - User Manual Verification 'Phase 3: Documentation Update' (Protocol in workflow.md)
