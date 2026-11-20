# Contributing to Samurai

Contributions, bug fixes, protocol extensions, and hardware dataplane improvements are welcome. All contributions to this repository are licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** unless explicitly agreed otherwise in writing.

---

## Development Setup & Verification

```bash
# Configure and build all native C++17 targets
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"

# Run core native self-tests
./build/control/samurai_control_selftest
./build/l4/test_tcp_sliding_window
./build/l7_emu_native/test_kernel_threaded_l7
./build/l7_emu_native/test_l2l3_astf
```

Before opening a Pull Request:
1. Follow the checklist in [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md).
2. Preserve all target-safety gates (`samurai/core/target_safety.cpp` / `core::ValidateTargetSafety`).
3. Keep all documentation under `docs/` in English.

---

## Open PR Proposals for New Contributors

The following engineering tasks are ready for incoming developers to pick up and submit as Pull Requests:

### 1. Telecom Dataplane Vectors & Protocols (CPU + CUDA)
- **GTP-U (`UDP/2152`):** Extend parallel TEID and inner-IP randomization across CPU (`samurai/cpu_native/`) and CUDA (`samurai/gpu_packet_cuda/kernels_l4.cuh`) templates for 4G EPC / 5G UPF load validation.
- **SCTP (`IP Proto 132`):** Implement 4G S1-AP and 5G NG-AP/F1-C signaling generators with SSE4.2 / CUDA warp-parallel CRC32c checksums.
- **SIP/RTP (VoIP/IMS):** Add L7 session templates and media stream pacing.
- **Diameter (`TCP/SCTP 3868`):** Add HSS/PCRF/SMF identity and charging signaling profiles.

### 2. Wire Protocol, Safety Gates & Deployment Hardening
- **RFC Suite Target-Safety Ordering & Live Metrics (`samurai/cli/main.cpp`, `samurai/cli/rfc_suite.cpp`):** Ensure `--run-rfc-suite` enforces `cli::Validate()` (`core::ValidateTargetSafety`) consistently across all paths and replace any remaining static placeholder metrics with measured runtime telemetry.
- **Closed-Loop RL Strategy Reporting (`samurai/control/daemon/master_main.cpp`):** Fix the final `closed_loop_result` JSON summary where the `kRl` strategy can be serialized as `"aimd"`.
- **Production `Dockerfile` Completeness (`Dockerfile`):** Include optional native protocol/reactor dependencies (`libnghttp2-dev`, `libngtcp2-dev`, `libnghttp3-dev`, `liburing-dev`) and package the `samurai` CLI and `samurai_telco_worker` binaries in the runtime image.
- **Versioned Wire Envelopes (`samurai/zmq/daemon/wire_protocol.h`):** Evolve packed `#pragma pack(push, 1)` structs (`JobEnvelopeV1`/`V2`, `TelcoGpuJobEnvelopeV1`, `TelcoJobPayload`) toward explicitly versioned, alignment-safe framing.
