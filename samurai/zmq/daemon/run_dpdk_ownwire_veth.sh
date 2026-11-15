#!/usr/bin/env bash
# E2E / recipe harness for the per-core DPDK custom_tcp own-wire path (H1/H2).
#
# This is the DPDK counterpart of run_customtcp_ownwire_veth.sh. It reuses the same
# test_customtcp_ownwire_l7 driver but selects the DPDK "tel" via
# SAMURAI_CUSTOM_TCP_WIRE=dpdk and points DPDK's software net_af_packet PMD at the
# veth. Functionally this exercises the shared port + N queues + rte_flow steering
# path (or its documented degrade to single-wire when the PMD lacks rte_flow).
#
# REQUIREMENTS (why this may only run on a real rig, not in CI):
#   * a DPDK build: configure with -DSAMURAI_WITH_DPDK=ON and libdpdk present.
#     Without it samurai::dpdk::available()==false and the engine silently keeps the
#     af_packet wire -- run_customtcp_ownwire_veth.sh already covers that case.
#   * DPDK EAL + net_af_packet usually need root / CAP_NET_RAW. The unprivileged
#     `unshare -r -n` used by the af_packet harness may NOT grant enough for EAL
#     hugepage/PMD init, so this script does NOT self-reexec into a userns by
#     default. Run it as root on a rig with a veth pair, or set OWNWIRE_UNSHARE=1 to
#     try the unprivileged path (best-effort).
#   * per-core steering (rte_flow port-mask) and real throughput need a proper NIC
#     with rte_flow + RSS; the software PMD validates the *control/data path*, not
#     per-core performance. On a PMD without rte_flow the engine degrades to the
#     single-wire af_packet fallback (still green, just not per-core).
#
# Topology (single namespace), identical to the af_packet harness:
#   v_cli  (DPDK net_af_packet bound here; NO IP)  <== veth ==>  v_srv (SRV_IP)
set -euo pipefail

TEST_BIN="${1:-}"
PROTO="${2:-http1}"   # http1 | http2
if [[ -z "${TEST_BIN}" || ! -x "${TEST_BIN}" ]]; then
  echo "usage: $0 /path/to/test_customtcp_ownwire_l7 [http1|http2]" >&2
  exit 2
fi
TEST_BIN="$(readlink -f "${TEST_BIN}")"
SCRIPT_PATH="$(readlink -f "$0")"

H2C_SERVER="${H2C_SERVER:-$(dirname "${SCRIPT_PATH}")/../../l7_emu_native/test_h2c_server.py}"
if [[ "${PROTO}" == "http2" || "${PROTO}" == "h2" ]]; then
  if [[ ! -f "${H2C_SERVER}" ]]; then
    echo "SKIP: h2c server not found at ${H2C_SERVER}" >&2
    exit 0
  fi
  if ! python3 -c 'import h2' 2>/dev/null; then
    echo "SKIP: python 'h2' module not installed (needed for the h2c server)" >&2
    exit 0
  fi
fi

# Optionally re-exec inside a fresh user+network namespace (best effort; EAL may
# still fail without hugepages/root -- see header). Default: run in the current
# (ideally root) namespace on a rig with a pre-created veth.
if [[ "${OWNWIRE_UNSHARE:-0}" == "1" && "${OWNWIRE_INNER:-}" != "1" ]]; then
  exec env OWNWIRE_INNER=1 OWNWIRE_UNSHARE=1 H2C_SERVER="${H2C_SERVER}" \
    unshare -r -n -- bash "${SCRIPT_PATH}" "${TEST_BIN}" "${PROTO}"
fi

SRV_IP="10.77.0.2"
SRC_IP="10.77.0.9"          # not assigned to any iface (avoids host RST)
PORT="18080"
FLOWS="${OWNWIRE_FLOWS:-4}"
IFACE="${OWNWIRE_IFACE:-v_cli}"
MADE_VETH=0

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "${SRV_PID}" 2>/dev/null || true
  [[ "${MADE_VETH}" == "1" ]] && ip link del v_cli 2>/dev/null || true
}
trap cleanup EXIT

# Create the veth pair if it is not already present (allows reuse of a rig's
# pre-provisioned interfaces via OWNWIRE_IFACE / OWNWIRE_NO_SETUP).
if [[ "${OWNWIRE_NO_SETUP:-0}" != "1" ]]; then
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

if [[ "${PROTO}" == "http2" || "${PROTO}" == "h2" ]]; then
  python3 "${H2C_SERVER}" "${SRV_IP}" "${PORT}" >/dev/null 2>&1 &
  SRV_PID=$!
  sleep 0.8
else
  python3 - "${SRV_IP}" "${PORT}" <<'PY' &
import sys, http.server, socketserver
ip, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer((ip, port), H) as s:
    s.serve_forever()
PY
  SRV_PID=$!
  sleep 0.6
fi

# --- DPDK own-wire selection ------------------------------------------------
export SAMURAI_CUSTOM_TCP_RX_IFACE="${IFACE}"      # src MAC (SIOCGIFHWADDR) + BPF degrade
export SAMURAI_CUSTOM_TCP_SRC_IP="${SRC_IP}"
export SAMURAI_CUSTOM_TCP_SRC_MAC="${CLI_MAC}"
export SAMURAI_CUSTOM_TCP_DST_MAC="${SRV_MAC}"
export SAMURAI_CUSTOM_TCP_MODE="required"
export SAMURAI_CUSTOM_TCP_BACKEND="af_packet"      # backend stays CustomTcp; wire=dpdk overrides the tel
export SAMURAI_CUSTOM_TCP_WIRE="dpdk"              # <-- selects the DPDK per-core wire
export SAMURAI_DPDK_PORT="0"
# Software PMD over the veth + no hugepages/PCI so it runs on a commodity box.
export SAMURAI_DPDK_VDEV="${SAMURAI_DPDK_VDEV:-net_af_packet,iface=${IFACE}}"
export SAMURAI_DPDK_EAL_ARGS="${SAMURAI_DPDK_EAL_ARGS:---no-huge --no-pci -l 0-3}"

export OWNWIRE_TARGET_IP="${SRV_IP}"
export OWNWIRE_TARGET_PORT="${PORT}"
export OWNWIRE_FLOWS="${FLOWS}"
export OWNWIRE_PROTO="${PROTO}"

echo "[harness] wire=dpdk proto=${PROTO} iface=${IFACE} v_cli=${CLI_MAC} v_srv=${SRV_MAC} srv=${SRV_IP}:${PORT} src=${SRC_IP} flows=${FLOWS}"
echo "[harness] EAL: vdev=${SAMURAI_DPDK_VDEV} args='${SAMURAI_DPDK_EAL_ARGS}'"
"${TEST_BIN}"
