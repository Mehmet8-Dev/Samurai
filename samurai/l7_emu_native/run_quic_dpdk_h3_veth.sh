#!/usr/bin/env bash
# Recipe harness for the per-core DPDK QUIC/H3 backend.
#
# Reuses test_kernel_threaded_h3 but points it at a non-loopback aioquic H3 server
# on a veth peer and flips the QUIC UDP-IO backend to DPDK via
# SAMURAI_STATEFUL_RUNTIME_BACKEND=dpdk (resolve_requested_backend reads that env
# first). This drives connect_udp_dpdk + the DPDK fan-out (manager opens N queues +
# per-queue UDP steering; each worker owns a queue) over DPDK's software
# net_af_packet PMD.
#
# REQUIREMENTS (rig-only, see run_dpdk_ownwire_veth.sh header for the full rationale):
#   * -DSAMURAI_WITH_DPDK=ON build with libdpdk. Without it the DPDK backend is a
#     stub (connect_udp_dpdk -> false) and QUIC falls back to the kernel socket, so
#     the existing run_kernel_threaded_h3_e2e.sh already covers that case.
#   * DPDK EAL + net_af_packet + aioquic (pip install aioquic). EAL usually needs
#     root/CAP_NET_RAW; run on a rig, not unprivileged CI.
#   * per-core UDP steering + throughput need a real NIC with rte_flow/RSS; the
#     software PMD validates the data path (threaded == serial parity), not perf.
#     On a PMD without rte_flow the fan-out degrades to serial -> single-queue DPDK
#     -> kernel (still green, just not per-core).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin="${1:-${H3_TEST_BIN:-$here/../zmq/build/l7_emu_native/test_kernel_threaded_h3}}"
IFACE="${QUIC_DPDK_IFACE:-v_cli}"

if [[ ! -x "$bin" ]]; then
  echo "test binary not found/executable: $bin" >&2
  echo "build it first: cmake --build <builddir> --target test_kernel_threaded_h3" >&2
  exit 2
fi
if ! python3 -c 'import aioquic' 2>/dev/null; then
  echo "SKIP: python 'aioquic' not installed (needed for the H3 server)" >&2
  exit 0
fi

SRV_IP="10.78.0.2"
SRC_IP="10.78.0.9"
MADE_VETH=0

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "${SRV_PID}" 2>/dev/null || true
  [[ -n "${SRV_OUT:-}" ]] && rm -f "${SRV_OUT}" 2>/dev/null || true
  [[ "${MADE_VETH}" == "1" ]] && ip link del v_cli 2>/dev/null || true
}
trap cleanup EXIT

# Provision the veth pair unless the rig already has it (QUIC_DPDK_NO_SETUP=1).
if [[ "${QUIC_DPDK_NO_SETUP:-0}" != "1" ]]; then
  ip link set lo up 2>/dev/null || true
  if ! ip link show v_cli >/dev/null 2>&1; then
    ip link add v_cli type veth peer name v_srv
    MADE_VETH=1
  fi
  ip addr add "${SRV_IP}/24" dev v_srv 2>/dev/null || true
  ip link set v_cli up
  ip link set v_srv up
  sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
  sysctl -wq net.ipv4.conf.v_srv.rp_filter=0 2>/dev/null || true
fi

CLI_MAC="$(ip link show "${IFACE}" | awk '/link\/ether/{print $2}')"
SRV_MAC="$(ip link show v_srv | awk '/link\/ether/{print $2}')"
ip neigh replace "${SRC_IP}" lladdr "${CLI_MAC}" dev v_srv 2>/dev/null || true

# aioquic H3 server on the veth peer; it prints "PORT <n>".
SRV_OUT="$(mktemp)"
python3 "$here/test_h3_server.py" "${SRV_IP}" >"${SRV_OUT}" 2>&1 &
SRV_PID=$!
port=""
for _ in $(seq 1 100); do
  port="$(sed -n 's/^PORT //p' "${SRV_OUT}" 2>/dev/null | head -1)"
  [[ -n "$port" ]] && break
  sleep 0.05
done
if [[ -z "$port" ]]; then
  echo "H3 server failed to start:" >&2
  cat "${SRV_OUT}" >&2
  exit 1
fi

# --- DPDK QUIC backend selection --------------------------------------------
export SAMURAI_STATEFUL_RUNTIME_BACKEND="dpdk"     # -> QuicUdpIoBackend::Dpdk
export SAMURAI_XDP_INTERFACE="${IFACE}"            # src MAC/IP + ARP resolution
export SAMURAI_DPDK_SRC_IP="${SRC_IP}"
export SAMURAI_DPDK_SRC_MAC="${CLI_MAC}"
export SAMURAI_DPDK_DST_MAC="${SRV_MAC}"
export SAMURAI_DPDK_PORT="0"
export SAMURAI_DPDK_VDEV="${SAMURAI_DPDK_VDEV:-net_af_packet,iface=${IFACE}}"
export SAMURAI_DPDK_EAL_ARGS="${SAMURAI_DPDK_EAL_ARGS:---no-huge --no-pci -l 0-3}"
export H3_TARGET_IP="${SRV_IP}"
export H3_TEST_PORT="${port}"

echo "[harness] backend=dpdk iface=${IFACE} v_cli=${CLI_MAC} v_srv=${SRV_MAC} srv=${SRV_IP}:${port} src=${SRC_IP}"
echo "[harness] EAL: vdev=${SAMURAI_DPDK_VDEV} args='${SAMURAI_DPDK_EAL_ARGS}'"
H3_TEST_PORT="${port}" "${bin}"
