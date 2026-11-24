#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  set -- samurai_master --help
fi

SRC_ROOT="${SAMURAI_SOURCE_DIR:-/opt/samurai/src}"
NATIVE_ARCH="${SAMURAI_NATIVE_ARCH:-ON}"

# Allow explicit opt-out (e.g. debugging inside the container with a custom shell)
if [ "${SAMURAI_SKIP_BUILD:-0}" = "1" ]; then
  exec "$@"
fi

# Pick a writable cache directory (persistent named volume at /var/cache/samurai by default;
# gracefully fall back to /tmp/samurai-cache if the default path is read-only under a custom UID).
CACHE_DIR="${SAMURAI_BUILD_CACHE_DIR:-/var/cache/samurai}"
if ! mkdir -p "${CACHE_DIR}/bin" "${CACHE_DIR}/lib" "${CACHE_DIR}/build" 2>/dev/null || [ ! -w "${CACHE_DIR}" ]; then
  CACHE_DIR="/tmp/samurai-cache"
  mkdir -p "${CACHE_DIR}/bin" "${CACHE_DIR}/lib" "${CACHE_DIR}/build"
fi

BIN_DIR="${CACHE_DIR}/bin"
LIB_DIR="${CACHE_DIR}/lib"
BUILD_DIR="${CACHE_DIR}/build"
STAMP_FILE="${CACHE_DIR}/.native-built"

export PATH="${BIN_DIR}:/usr/local/bin:${PATH}"
export LD_LIBRARY_PATH="${LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export SAMURAI_SKILLS_DIR="${SAMURAI_SKILLS_DIR:-/usr/local/share/samurai/skills}"
export SAMURAI_RL_DIR="${SAMURAI_RL_DIR:-/usr/local/share/samurai/rl}"

# Compute a host + source + toolchain key so switching CPUs, image versions,
# or mounting a fresh GPU runtime invalidates stale binaries cleanly.
SRC_STAMP="unknown"
if [ -f /opt/samurai/.source-stamp ]; then
  SRC_STAMP="$(cat /opt/samurai/.source-stamp)"
fi
ARCH_NAME="$(uname -m 2>/dev/null || echo unknown)"
CPU_FLAGS="$(grep -m1 -E '^(flags|Features)[[:space:]]*:' /proc/cpuinfo 2>/dev/null || true)"
HAS_NVCC="0"
if command -v nvcc >/dev/null 2>&1 || [ -x /usr/local/cuda/bin/nvcc ]; then
  HAS_NVCC="1"
fi
BUILD_KEY="$(printf '%s|%s|%s|%s|%s' "${SRC_STAMP}" "${ARCH_NAME}" "${CPU_FLAGS}" "${HAS_NVCC}" "${NATIVE_ARCH}" | sha256sum | awk '{print $1}')"

need_build() {
  [ ! -x "${BIN_DIR}/samurai" ] || [ ! -x "${BIN_DIR}/samurai_mcp" ] || [ ! -f "${STAMP_FILE}" ] || [ "$(cat "${STAMP_FILE}" 2>/dev/null || true)" != "${BUILD_KEY}" ]
}

build_host_binaries() {
  local jobs
  jobs="$(nproc 2>/dev/null || echo 2)"
  # IMPORTANT: Write all build output to stderr (>&2) so MCP JSON-RPC stdout is never polluted.
  echo "[samurai] Compiling from source for host hardware (arch=${ARCH_NAME}, SAMURAI_NATIVE_ARCH=${NATIVE_ARCH}, jobs=${jobs})..." >&2

  cmake -S "${SRC_ROOT}/samurai" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DSAMURAI_NATIVE_ARCH="${NATIVE_ARCH}" 1>&2

  local targets=(
    samurai
    samurai_mcp
    samurai_master
    samurai_slave
    samurai_cpu_worker
    samurai_afpacket_worker
    samurai_afxdp_worker
    samurai_dpdk_worker
    samurai_gpu_worker
    samurai_doca_worker
    samurai_l7_worker
    samurai_scenario_worker
    samurai_defense_worker
    samurai_telco_worker
    test_100k_tcp_flows
    test_1m_tcp_flows
    bench_l7_stateful_userspace
  )

  for opt_dir in gpu_packet_cuda gpu_packet_cuda_defense xdp_sender; do
    if [ -d "${BUILD_DIR}/optional/CMakeFiles/${opt_dir}.dir" ]; then
      targets+=("${opt_dir}")
    fi
  done

  cmake --build "${BUILD_DIR}" -j "${jobs}" --target "${targets[@]}" 1>&2

  cp -f "${BUILD_DIR}/cli/samurai" "${BIN_DIR}/samurai"
  cp -f "${BUILD_DIR}/mcp/samurai_mcp" "${BIN_DIR}/samurai_mcp"
  cp -f "${BUILD_DIR}/control/daemon/samurai_master" "${BIN_DIR}/samurai_master"
  cp -f "${BUILD_DIR}/control/daemon/samurai_slave" "${BIN_DIR}/samurai_slave"
  for w in "${BUILD_DIR}"/zmq/samurai_*_worker; do
    [ -x "$w" ] && cp -f "$w" "${BIN_DIR}/"
  done
  cp -f "${BUILD_DIR}/l4/test_100k_tcp_flows" "${BIN_DIR}/samurai_bench_100k_tcp"
  cp -f "${BUILD_DIR}/l4/test_1m_tcp_flows" "${BIN_DIR}/samurai_bench_1m_tcp"
  cp -f "${BUILD_DIR}/zmq/bench_l7_stateful_userspace" "${BIN_DIR}/samurai_bench_l7"

  for so_file in \
    "${BUILD_DIR}/optional/libgpu_packet_cuda.so" \
    "${BUILD_DIR}/optional/libgpu_packet_cuda_defense.so" \
    "${BUILD_DIR}/optional/xdp_sender.so"; do
    [ -f "${so_file}" ] && cp -f "${so_file}" "${LIB_DIR}/"
  done

  printf '%s\n' "${BUILD_KEY}" > "${STAMP_FILE}.tmp"
  mv -f "${STAMP_FILE}.tmp" "${STAMP_FILE}"
  echo "[samurai] Host-native build cached at ${BIN_DIR}." >&2
}

if need_build; then
  if command -v flock >/dev/null 2>&1; then
    exec 9>"${CACHE_DIR}/.build.lock"
    flock 9
    if need_build; then
      build_host_binaries
    fi
    flock -u 9
    exec 9>&-
  else
    build_host_binaries
  fi
fi

exec "$@"
