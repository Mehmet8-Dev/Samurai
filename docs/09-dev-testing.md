# 09 - Development, CMake Build System & Native Testing

Samurai development, continuous integration, and validation workflows utilize a modern CMake build system (C++17) coupled with self-contained native C++ test binaries.

---

## 1. Building the Project

```bash
# 1. Create build directory
mkdir -p build && cd build

# 2. Configure with CMake (Release mode recommended for line-rate performance)
cmake .. -DCMAKE_BUILD_TYPE=Release

# 3. Compile all targets in parallel
make -j$(nproc)
```

---

## 2. Running Native C++ Test Suites

Each major architectural layer includes a standalone native validation harness:

```bash
# 1. Control Plane, Shard Engine, and RPC Wire Tests
./build/ddos_samurai/control/samurai_control_selftest

# 2. L7 Stateful Transport, QUIC, and Custom TCP Tests
./build/ddos_samurai/l7_emu_native/samurai_l7_selftest

# 3. Scenario Engine (DSL, Compiler, and SLA Gates)
./build/ddos_samurai/scenario_engine_native/samurai_scenario_engine_selftest

# 4. Licensing, HMAC, and Access Token Tests
./build/ddos_samurai/licensing/samurai_licensing_selftest
```

---

## 3. Engineering & Performance Standards

- **Language Standard:** Strict C++17 without proprietary compiler extensions.
- **Dependencies:** ZeroMQ (`libzmq`), OpenSSL (TLS 1.3 / HMAC / SHA-256), `libbpf` (AF_XDP).
- **Zero-Allocation Paradigm:** Zero runtime allocations (`malloc`/`new`) along fastpath TX/RX packet pipelines.
- **Lock-Free Concurrency:** Single-Producer Single-Consumer (SPSC) ring buffers and lock-striped shard structures.
