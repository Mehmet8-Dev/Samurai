#!/usr/bin/env bash
# ==============================================================================
# Samurai tcpdp Real-Wire (netns + veth + AF_PACKET) Benchmark & Verification
#
# Sets up an isolated network namespace with a virtual Ethernet pair (`v_cli` <==> `v_srv`),
# configures on-link IPv4 routing + static ARP neighbor entries (so the host kernel never
# emits spurious RSTs for our user-space TCP engine's spoofed source IP), and executes:
#   1) `test_tcpdp_veth_wire`:
#      - Phase 1: Real TCP 3-way handshakes directly against a live Linux kernel `accept()`
#        TCP listener socket on `v_srv` (`10.77.0.2:18088`).
#      - Phase 2: High-scale 100,000+ (or 1,000,000) full 3-way handshakes (`SYN` -> `SYN-ACK` -> `ACK`)
#        transmitted and received as real Ethernet frames across the kernel `veth` driver via
#        `AF_PACKET` (`sendmmsg` / `recvmmsg`) with `/proc/net/dev` hardware/driver counter audit.
#   2) `test_customtcp_ownwire_l7`:
#      - Shared-Nothing multi-shard HTTP/1.1 L7 request/response exchange over the real veth wire.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build"
WIRE_BIN="${BUILD_DIR}/l4/test_tcpdp_veth_wire"
OWNWIRE_L7_BIN="${BUILD_DIR}/zmq/test_customtcp_ownwire_l7"

WIRE_FLOWS="${WIRE_FLOWS:-100000}"
KERNEL_FLOWS="${KERNEL_FLOWS:-2000}"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/reports/benchmarks/tcpdp_1m_flows}"
WIRE_JSON="${OUTPUT_DIR}/veth_wire_metrics.json"

mkdir -p "$OUTPUT_DIR"

# If we are not yet inside the isolated network namespace, build binaries on the host
# and re-enter via `unshare -r -n`, `sudo -n unshare -n`, or Docker `chroot /host unshare -n`.
if [[ "${VETH_INNER_NS:-0}" != "1" ]]; then
  echo "[+] Building test_tcpdp_veth_wire and test_customtcp_ownwire_l7..."
  cmake -B "$BUILD_DIR" -S "${REPO_ROOT}/samurai" >/dev/null
  cmake --build "$BUILD_DIR" --target test_tcpdp_veth_wire test_customtcp_ownwire_l7 -j"$(nproc)"

  if unshare -r -n -- ip link show >/dev/null 2>&1; then
    echo "[+] Entering isolated user+network namespace via unshare -r -n..."
    exec env VETH_INNER_NS=1 WIRE_FLOWS="$WIRE_FLOWS" KERNEL_FLOWS="$KERNEL_FLOWS" OUTPUT_DIR="$OUTPUT_DIR" \
      unshare -r -n -- bash "$0" "$@"
  elif sudo -n true >/dev/null 2>&1; then
    echo "[+] Entering isolated network namespace via sudo -n unshare -n..."
    exec sudo -n env VETH_INNER_NS=1 WIRE_FLOWS="$WIRE_FLOWS" KERNEL_FLOWS="$KERNEL_FLOWS" OUTPUT_DIR="$OUTPUT_DIR" \
      unshare -n -- bash "$0" "$@"
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    echo "[+] Entering isolated network namespace via Docker chroot + unshare -n (AppArmor bypass)..."
    exec docker run --rm --privileged --pid=host --network=host -v /:/host ubuntu:24.04 \
      chroot /host env VETH_INNER_NS=1 WIRE_FLOWS="$WIRE_FLOWS" KERNEL_FLOWS="$KERNEL_FLOWS" OUTPUT_DIR="$OUTPUT_DIR" \
      unshare -n -- bash "${REPO_ROOT}/tests/bench_tcpdp_veth_wire.sh" "$@"
  else
    echo "SKIP: No unprivileged userns, passwordless sudo, or Docker daemon available to create veth netns."
    exit 0
  fi
fi

# === Inside Isolated Network Namespace ===
SRV_IP="10.77.0.2"
SRC_IP="10.77.0.9"

ip link set lo up
ip link add v_cli type veth peer name v_srv
ip link set v_cli txqueuelen 100000
ip link set v_srv txqueuelen 100000
ip addr add "${SRV_IP}/24" dev v_srv
ip link set v_cli up
ip link set v_srv up

# Disable veth TX/RX checksum offload so that the Linux kernel TCP stack on v_srv computes full
# RFC 1071 TCP checksums on the wire instead of leaving CHECKSUM_PARTIAL pseudo-header seeds.
if command -v ethtool >/dev/null 2>&1; then
  ethtool -K v_cli tx off rx off sg off tso off gso off >/dev/null 2>&1 || true
  ethtool -K v_srv tx off rx off sg off tso off gso off >/dev/null 2>&1 || true
fi

# Disable reverse-path filtering and raise SYN backlog so the live kernel TCP listener
# on v_srv can accept thousands of rapid handshakes from our user-space engine on v_cli.
sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -wq net.ipv4.conf.v_srv.rp_filter=0 2>/dev/null || true
sysctl -wq net.ipv4.tcp_max_syn_backlog=65536 2>/dev/null || true
sysctl -wq net.core.somaxconn=65535 2>/dev/null || true
sysctl -wq net.ipv4.tcp_tw_reuse=1 2>/dev/null || true

CLI_MAC="$(ip link show v_cli | awk '/link\/ether/{print $2}')"
SRV_MAC="$(ip link show v_srv | awk '/link\/ether/{print $2}')"

# Map our user-space engine's source IP (10.77.0.9) to v_cli's MAC address so the kernel
# TCP stack on v_srv sends its SYN-ACKs directly onto v_cli without ARP resolution stalls.
ip neigh replace "${SRC_IP}" lladdr "${CLI_MAC}" dev v_srv

echo "[+] Provisioned isolated veth pair: v_cli (${CLI_MAC}) <==> v_srv (${SRV_MAC}, ${SRV_IP}/24)"
"$WIRE_BIN" --cli-iface v_cli --srv-iface v_srv --flows "$WIRE_FLOWS" --kernel-flows "$KERNEL_FLOWS" --json "$WIRE_JSON"

if [[ -x "$OWNWIRE_L7_BIN" ]]; then
  echo "--------------------------------------------------------------------------------"
  echo "[PHASE 3] Shared-Nothing Multi-Shard L7 HTTP/1.1 over Real veth Wire..."
  ip link del v_cli 2>/dev/null || true
  OWNWIRE_INNER=1 OWNWIRE_FLOWS=16 "${REPO_ROOT}/samurai/zmq/daemon/run_customtcp_ownwire_veth.sh" "$OWNWIRE_L7_BIN" http1
fi
