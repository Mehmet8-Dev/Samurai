# ADR: Native C++ CPU Packet Engine with Python Facade

- Date: 2026-04-04
- Status: Accepted

## Context

`ddos_samurai.cpu_packet_engine` started as a pure-Python packet construction module. It provided good portability and API stability, but packet construction, pool generation, and fragmentation became a measurable bottleneck for high-rate CPU sender paths.

The project also needed:

- a zero-copy packet-pool path for large batches
- explicit GIL release during native compute
- protocol-safe serialization without packed-struct aliasing risks
- preservation of the existing Python-facing API used by tests, orchestrator, and sender code

## Decision

We moved the packet construction core to a native C++ module exposed as `ddos_samurai._cpu_packet_engine_native` and retained `ddos_samurai.cpu_packet_engine` as the public Python facade.

Key decisions:

- Keep `create_packet(...) -> bytes` for compatibility.
- Keep `generate_packet_pool(...) -> (bytes, int)` for compatibility.
- Add `generate_packet_pool_view(...) -> (memoryview, int)` as the zero-copy hot path.
- Use vendored `pybind11` for binding ergonomics and deterministic builds.
- Release the GIL around native packet construction and pool generation.
- Use explicit endian-safe byte writers instead of packed header overlays or `reinterpret_cast` struct views.
- Move performance-critical orchestrator pool generation to `generate_packet_pool_view`.

## Consequences

### Positive

- Higher throughput on CPU packet generation paths.
- Lower Python allocation pressure for packet pool generation.
- Better multi-thread cooperation because native compute releases the GIL.
- Safer wire serialization across x86_64 and ARM-class systems.
- Public Python API remains stable for most call sites.

### Tradeoffs

- Build complexity increased because the module now depends on a native extension.
- Debugging packet-generation internals may require switching between Python and C++ layers.
- Some tests that depended on Python monkeypatching of internal helpers are no longer valid once high-level generation is fully native.

## Validation

The decision is validated by:

- CPU packet engine contract tests
- RFC compliance and negative suites
- benchmark coverage for both bytes pool and zero-copy pool view
- dedicated regression checks for memory pressure and GIL release behavior

## Follow-up

- Extend benchmark reporting to compare `generate_packet_pool_view` against the bytes pool in CI artifacts.
- Add more sender-side integration coverage for memoryview-backed packet pools.
