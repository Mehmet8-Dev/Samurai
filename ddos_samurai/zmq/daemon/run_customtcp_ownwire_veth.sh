#!/usr/bin/env bash
# E2E harness for the shared-nothing custom_tcp own-wire path (per-shard AF_PACKET).
#
# Builds a private network namespace with a veth pair and a live HTTP server, then
# runs test_customtcp_ownwire_l7 so the engine's per-shard af_packet wire completes
# real TCP handshakes + HTTP requests over the wire. No host privileges required:
# it self-reexecs under `unshare -r -n` (user+net namespace) where we hold
# CAP_NET_RAW/CAP_NET_ADMIN over the throwaway veth.
#
# Topology (single namespace):
#   v_cli  (our side, AF_PACKET bound here; NO IP so the host stack never RSTs the
#           spoofed src)             <== veth ==>   v_srv (server side, SRV_IP)
#   src IP SRC_IP is not owned by anyone; a static neigh on v_srv maps it to v_cli's
#   MAC so the server can ARP-resolve its SYN-ACK back onto our capture socket.
set -euo pipefail

TEST_BIN="${1:-}"
PROTO="${2:-http1}"   # http1 | http2
if [[ -z "${TEST_BIN}" || ! -x "${TEST_BIN}" ]]; then
  echo "usage: $0 /path/to/test_customtcp_ownwire_l7 [http1|http2]" >&2
  exit 2
fi
TEST_BIN="$(readlink -f "${TEST_BIN}")"
SCRIPT_PATH="$(readlink -f "$0")"

# The shared-nothing own-wire path drives both HTTP/1.1 and HTTP/2 per shard. (H2
# was previously skipped here because multi-shard H2-over-tcpdp appeared to
# livelock; that was actually the engine closing its own stdout fd -- the result
# was produced but never printed. The real L4 stall was already fixed by the
# sliding-window sender, and H2 multi-shard is now verified over the wire.)
# For H2 we need a real HTTP/2 (h2c) server; locate it relative to this script.
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

# Re-exec inside a fresh user+network namespace (unprivileged).
if [[ "${OWNWIRE_INNER:-}" != "1" ]]; then
  exec env OWNWIRE_INNER=1 H2C_SERVER="${H2C_SERVER}" unshare -r -n -- bash "${SCRIPT_PATH}" "${TEST_BIN}" "${PROTO}"
fi

SRV_IP="10.77.0.2"
SRC_IP="10.77.0.9"          # not assigned to any iface (avoids host RST)
PORT="18080"
FLOWS="${OWNWIRE_FLOWS:-4}"

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "${SRV_PID}" 2>/dev/null || true
}
trap cleanup EXIT

ip link set lo up
ip link add v_cli type veth peer name v_srv
ip addr add "${SRV_IP}/24" dev v_srv
ip link set v_cli up
ip link set v_srv up

# Relax reverse-path filtering so the server accepts SYNs from the spoofed on-link src.
sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -wq net.ipv4.conf.v_srv.rp_filter=0 2>/dev/null || true

# /sys/class/net is the host sysfs (not remapped for this netns), so read MACs
# from `ip link show` instead.
CLI_MAC="$(ip link show v_cli | awk '/link\/ether/{print $2}')"
SRV_MAC="$(ip link show v_srv | awk '/link\/ether/{print $2}')"

# Server must ARP-resolve our (unowned) src IP -> point it at the capture side.
ip neigh replace "${SRC_IP}" lladdr "${CLI_MAC}" dev v_srv

if [[ "${PROTO}" == "http2" || "${PROTO}" == "h2" ]]; then
  # Real HTTP/2 cleartext (h2c) server bound to the server IP + fixed port.
  python3 "${H2C_SERVER}" "${SRV_IP}" "${PORT}" >/dev/null 2>&1 &
  SRV_PID=$!
  sleep 0.8
else
  # Minimal always-200 HTTP/1.1 server bound to the server IP.
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

export SAMURAI_CUSTOM_TCP_RX_IFACE="v_cli"
export SAMURAI_CUSTOM_TCP_SRC_IP="${SRC_IP}"
export SAMURAI_CUSTOM_TCP_DST_MAC="${SRV_MAC}"
export SAMURAI_CUSTOM_TCP_MODE="required"
export SAMURAI_CUSTOM_TCP_BACKEND="af_packet"
export OWNWIRE_TARGET_IP="${SRV_IP}"
export OWNWIRE_TARGET_PORT="${PORT}"
export OWNWIRE_FLOWS="${FLOWS}"
export OWNWIRE_PROTO="${PROTO}"

echo "[harness] proto=${PROTO} v_cli=${CLI_MAC} v_srv=${SRV_MAC} srv=${SRV_IP}:${PORT} src=${SRC_IP} flows=${FLOWS}"
"${TEST_BIN}"
