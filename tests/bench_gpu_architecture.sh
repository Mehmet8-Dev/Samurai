#!/usr/bin/env bash
# ==============================================================================
# GPU Architecture & Coprocessor Benchmark Suite
# ==============================================================================
# Benchmarks:
#   * Commodity GPU GeForce BAR1 P2P DMA Packet Engine
#   * QUIC CUDA/SIMD Cryptographic Coprocessor Engine
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$ROOT_DIR/tests/native_gpu/test_gpu_architecture"
JSON_OUT="$ROOT_DIR/docs/gpu_architecture_benchmark_results.json"


if [[ ! -x "$BIN" ]]; then
  echo "[BUILD] Compiling test_gpu_architecture..."
  g++ -std=c++17 -O3 "$ROOT_DIR/tests/native_gpu/test_gpu_architecture.cpp" \
    -I "$ROOT_DIR" \
    -I "$ROOT_DIR/samurai/l7_emu_native" \
    -I "$ROOT_DIR/samurai/core" \
    -I "$ROOT_DIR/samurai/l4" \
    -I "$ROOT_DIR/samurai" \
    -L "$ROOT_DIR/samurai/build/l7_emu_native" \
    -L "$ROOT_DIR/samurai/build/l4" \
    -L "$ROOT_DIR/samurai/build/core" \
    -L "$ROOT_DIR/samurai/build/af_packet" \
    -Wl,--whole-archive -lsamurai_l7emu -Wl,--no-whole-archive \
    -lsamurai_l4 -lsamurai_core -laf_packet_static -lssl -lcrypto -lpthread -ldl -lcudart \
    -o "$BIN"
fi

echo "[BENCHMARK] Executing GPU Architecture Benchmark Suite..."
"$BIN" --json-file "$JSON_OUT" "$@"
