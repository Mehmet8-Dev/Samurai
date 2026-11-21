#!/usr/bin/env bash
# Samurai — One-Command Reproducible Benchmark Suite
#
# Runs Samurai's verified L4 userspace TCP, L7 Shared-Nothing HTTP/1.1 & HTTP/2,
# and RFC 2544/3511/8219 benchmark harnesses on your machine and outputs a
# shareable Markdown report (ready to paste into GitHub Discussions).
#
# Usage:
#   ./scripts/reproduce-benchmarks.sh           # Quick (~5s): 100k TCP + 10k L7 + RFC suite
#   ./scripts/reproduce-benchmarks.sh --full    # Full (~45s): includes 1,000,000 active TCP flows

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${SAMURAI_BUILD_DIR:-${ROOT_DIR}/build}"
MODE="quick"
OUT_MD="${ROOT_DIR}/reports/reproduced_benchmark_summary.md"

for arg in "$@"; do
  case "$arg" in
    --full) MODE="full" ;;
    --quick) MODE="quick" ;;
    -h|--help)
      echo "Usage: $0 [--quick | --full]"
      echo "  --quick  Run 100k TCP flow check, 10k L7 H1/H2 benchmark, and RFC suite (~5s)"
      echo "  --full   Also run the full 1,000,000 active TCP flow scaling benchmark (~45s)"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "$OUT_MD")"

# Build missing targets automatically if needed
NEED_BUILD=0
for bin in \
  "${BUILD_DIR}/cli/samurai" \
  "${BUILD_DIR}/l4/test_100k_tcp_flows" \
  "${BUILD_DIR}/l4/test_1m_tcp_flows" \
  "${BUILD_DIR}/zmq/bench_l7_stateful_userspace"; do
  if [[ ! -x "$bin" ]]; then
    NEED_BUILD=1
  fi
done

if [[ "$NEED_BUILD" -eq 1 ]]; then
  echo "[samurai] Building native C++17 benchmark targets..."
  cmake -B "$BUILD_DIR" -S "${ROOT_DIR}/samurai" -DCMAKE_BUILD_TYPE=Release
  cmake --build "$BUILD_DIR" -j"$(nproc)" --target \
    samurai samurai_cpu_worker test_100k_tcp_flows test_1m_tcp_flows bench_l7_stateful_userspace
fi

CPU_MODEL="$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null | xargs || uname -m)"
CORES="$(nproc 2>/dev/null || echo unknown)"
KERNEL="$(uname -r)"
MEM_TOTAL="$(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo 2>/dev/null || echo unknown)"
CXX_VER="$(g++ --version 2>/dev/null | head -n1 || c++ --version 2>/dev/null | head -n1 || echo unknown)"
DATE_UTC="$(date -u '+%Y-%m-%d %H:%M UTC')"

echo "================================================================================"
echo " Samurai Reproducible Benchmark Suite (${MODE} mode)"
echo " CPU: ${CPU_MODEL} (${CORES} logical cores) | RAM: ${MEM_TOTAL} | Kernel: ${KERNEL}"
echo "================================================================================"

echo ""
echo "[1/3] Running L4 Userspace TCP 100k Flow Shard & Lockless Lookup Benchmark..."
TCP_100K_OUT="$("${BUILD_DIR}/l4/test_100k_tcp_flows" 2>&1)"
echo "$TCP_100K_OUT" | tail -n 10

TCP_1M_OUT=""
if [[ "$MODE" == "full" ]]; then
  echo ""
  echo "[1b/3] Running Full 1,000,000 Active TCP Flows Scaling Benchmark (605 B/flow target)..."
  TCP_1M_OUT="$("${BUILD_DIR}/l4/test_1m_tcp_flows" 2>&1)"
  echo "$TCP_1M_OUT" | tail -n 25
fi

echo ""
echo "[2/3] Running L7 Shared-Nothing Stateful Userspace Benchmark (HTTP/1.1 & HTTP/2, 10,000 flows)..."
L7_H1_OUT="$("${BUILD_DIR}/zmq/bench_l7_stateful_userspace" --proto h1 --flows 10000 2>&1)"
L7_H2_OUT="$("${BUILD_DIR}/zmq/bench_l7_stateful_userspace" --proto h2 --flows 10000 2>&1)"
echo "$L7_H1_OUT" | tail -n 10
echo "$L7_H2_OUT" | tail -n 10

echo ""
echo "[3/3] Running RFC 2544 / 3511 / 8219 Compliance Suite..."
RFC_OUT="$("${BUILD_DIR}/cli/samurai" --run-rfc-suite all 2>&1)"
echo "$RFC_OUT" | head -n 25

cat > "$OUT_MD" <<EOF
# Samurai Reproduced Benchmark Report

- **Date:** ${DATE_UTC}
- **Mode:** \`${MODE}\`
- **CPU:** ${CPU_MODEL} (${CORES} logical cores)
- **Memory:** ${MEM_TOTAL}
- **Kernel:** Linux \`${KERNEL}\`
- **Compiler:** \`${CXX_VER}\`

> **Methodology boundary:** L4 TCP flow and L7 H1/H2 benchmarks below measure Samurai's in-memory userspace dataplane (\`TcpDataplaneCore\` + \`InMemoryShardPeer\`) with real RFC 1071 checksums, RFC 7230 parsing, and \`nghttp2\` framing — independent of physical NIC line rates.

## 1. L4 Userspace TCP — 100k Flow 64-Shard Scaling

\`\`\`text
${TCP_100K_OUT}
\`\`\`
EOF

if [[ "$MODE" == "full" ]]; then
cat >> "$OUT_MD" <<EOF

## 1b. L4 Userspace TCP — 1,000,000 Active Flows Scaling

\`\`\`text
${TCP_1M_OUT}
\`\`\`
EOF
fi

cat >> "$OUT_MD" <<EOF

## 2. L7 Stateful Userspace (HTTP/1.1 & HTTP/2, 10,000 flows)

\`\`\`text
$(echo "$L7_H1_OUT" | tail -n 12)

$(echo "$L7_H2_OUT" | tail -n 12)
\`\`\`

## 3. RFC 2544 / 3511 / 8219 Compliance Suite

${RFC_OUT}
EOF

echo ""
echo "================================================================================"
echo " Report saved to: ${OUT_MD}"
echo " Share your hardware results in GitHub Discussions:"
echo "   https://github.com/Mehmet8-Dev/Samurai/discussions"
echo "================================================================================"
