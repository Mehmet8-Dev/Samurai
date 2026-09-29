#!/usr/bin/env bash
# End-to-end runner for the kernel_socket H2 threaded driver.
#
# Runs the full reactor x transport matrix against real Python HTTP/2 servers:
#   * cleartext h2c   -> test_h2c_server.py     (Hyper `h2` stack)
#   * TLS (ALPN h2)   -> test_h2_tls_server.py  (memory-BIO crypto path)
# and, for the TLS server, the opt-in kTLS socket-BIO path. Where the host has no
# TCP "tls" ULP the engine falls back to memory-BIO, so to still exercise the
# socket-BIO reactor integration (incremental SSL_do_handshake on the fd,
# SSL_read/SSL_write, io_uring PollReadiness) we force it with
# SAMURAI_H2_KTLS_FORCE_SOCKET_BIO=1 (in-process crypto over the socket BIO; the
# byte path is otherwise identical to a real kTLS session).
#
# Pass the built binary path as $1, or set H2_TEST_BIN. Defaults to the in-tree
# zmq build output.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin="${1:-${H2_TEST_BIN:-$here/../zmq/build/l7_emu_native/test_kernel_threaded_h2}}"

if [[ ! -x "$bin" ]]; then
  echo "test binary not found/executable: $bin" >&2
  echo "build it first: cmake --build <builddir> --target test_kernel_threaded_h2" >&2
  exit 2
fi

start_server() {  # $1=script -> echoes "pid port"
  local out pid port
  out="$(mktemp)"
  python3 "$here/$1" >"$out" 2>&1 &
  pid=$!
  port=""
  for _ in $(seq 1 100); do
    port="$(sed -n 's/^PORT //p' "$out" 2>/dev/null | head -1)"
    [[ -n "$port" ]] && break
    sleep 0.05
  done
  if [[ -z "$port" ]]; then
    echo "server $1 failed to start:" >&2
    cat "$out" >&2
    kill "$pid" 2>/dev/null || true
    rm -f "$out"
    exit 1
  fi
  echo "$pid $port $out"
}

read -r h2c_pid h2c_port h2c_out < <(start_server test_h2c_server.py)
read -r tls_pid tls_port tls_out < <(start_server test_h2_tls_server.py)
cleanup() {
  kill "$h2c_pid" "$tls_pid" 2>/dev/null || true
  rm -f "$h2c_out" "$tls_out"
}
trap cleanup EXIT

echo "h2c server  pid=$h2c_pid port=$h2c_port"
echo "h2-tls srv  pid=$tls_pid port=$tls_port"

fails=0
run() {  # $1=label ; rest=env assignments
  local label="$1"; shift
  echo "--- $label ---"
  if env "$@" "$bin"; then :; else fails=$((fails + 1)); echo "  ^ FAILED"; fi
}

run "io_uring  plaintext"          H2_TEST_PORT="$h2c_port"
run "epoll     plaintext"          H2_TEST_EPOLL=1 H2_TEST_PORT="$h2c_port"
run "io_uring  TLS  (mem-BIO)"     H2_TEST_TLS=1 H2_TEST_PORT="$tls_port"
run "epoll     TLS  (mem-BIO)"     H2_TEST_TLS=1 H2_TEST_EPOLL=1 H2_TEST_PORT="$tls_port"
run "io_uring  kTLS (socket-BIO)"  H2_TEST_TLS=1 H2_TEST_KTLS=1 SAMURAI_H2_KTLS_FORCE_SOCKET_BIO=1 H2_TEST_PORT="$tls_port"
run "epoll     kTLS (socket-BIO)"  H2_TEST_TLS=1 H2_TEST_KTLS=1 SAMURAI_H2_KTLS_FORCE_SOCKET_BIO=1 H2_TEST_EPOLL=1 H2_TEST_PORT="$tls_port"

if [[ "$fails" -ne 0 ]]; then
  echo "H2 E2E MATRIX FAILED ($fails)"
  exit 1
fi
echo "H2 E2E MATRIX PASSED (6/6)"
