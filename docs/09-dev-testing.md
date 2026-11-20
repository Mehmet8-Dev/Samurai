# 09 - Development, CMake Build System & Native Testing

Samurai development, continuous integration, and validation workflows utilize a modern CMake build system (C++17) coupled with self-contained native C++ test binaries.

---

## 1. Building the Project

```bash
# Configure with CMake from repository root (Release mode recommended for line-rate performance)
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release

# Compile all targets in parallel
cmake --build build -j"$(nproc)"
```

---

## 2. Running Native C++ Test Suites

Each major architectural layer includes standalone native validation binaries:

```bash
# 1. Control Plane, Shard Engine, and RPC Wire Tests
./build/control/samurai_control_selftest

# 2. L7 Stateful Transport, QUIC, and Custom TCP Tests
./build/l7_emu_native/test_l2l3_astf
./build/l7_emu_native/test_kernel_threaded_l7

# 3. L4 Userspace TCP Sliding Window & SACK Recovery
./build/l4/test_tcp_sliding_window
```

---

## 3. Engineering & Performance Standards

- **Language Standard:** Strict C++17 without proprietary compiler extensions.
- **Dependencies:** ZeroMQ (`libzmq`), OpenSSL (TLS 1.3 / HMAC / SHA-256), `libbpf` (AF_XDP).
- **Zero-Allocation Paradigm:** Zero runtime allocations (`malloc`/`new`) along fastpath TX/RX packet pipelines.
- **Lock-Free Concurrency:** Single-Producer Single-Consumer (SPSC) ring buffers and lock-striped shard structures.
