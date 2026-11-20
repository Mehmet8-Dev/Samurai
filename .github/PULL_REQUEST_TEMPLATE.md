## Summary

<!-- Describe what this PR changes and why. Reference the related issue or proposal ID if applicable. -->

## Architectural Layer

- [ ] Core / CLI (`samurai/core`, `samurai/cli`)
- [ ] Control Plane / Orchestrator (`samurai/control`, `samurai/orchestrator`)
- [ ] Dataplane / Workers (`samurai/l4`, `samurai/l7_emu_native`, `samurai/af_packet`, `samurai/zmq`, `samurai/gpu_packet_cuda`, `samurai/telecom`)
- [ ] Build / CI / Containers (`CMakeLists.txt`, `Dockerfile`, `.github/`)
- [ ] Documentation / Tests (`docs/`, `tests/`)

## Verification Checklist

- [ ] Built cleanly with CMake (`cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`)
- [ ] Native selftests pass (`./build/control/samurai_control_selftest`, `./build/l4/test_tcp_sliding_window`, `./build/l7_emu_native/test_l2l3_astf`, etc.)
- [ ] Python / E2E tests updated and passing (`pytest`)
- [ ] Target safety policy preserved (`core::ValidateTargetSafety` / `--deny-target` gates remain intact)
- [ ] Documentation in `docs/` updated in English (if CLI flags, wire protocol, or architecture changed)
- [ ] Contribution licensed under GNU AGPL-3.0 (see `LICENSE`)
