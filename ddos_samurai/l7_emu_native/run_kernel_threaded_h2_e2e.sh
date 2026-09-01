#!/usr/bin/env bash
# End-to-end runner for the kernel_socket H2 threaded driver.
#
# Starts the real h2c (cleartext HTTP/2, prior-knowledge) server backed by the
# Hyper `h2` protocol stack, hands its ephemeral port to test_kernel_threaded_h2
# via H2_TEST_PORT, and runs the test. Pass the built binary path as $1, or set
# H2_TEST_BIN. Defaults to the in-tree zmq build output.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin="${1:-${H2_TEST_BIN:-$here/../zmq/build/l7_emu_native/test_kernel_threaded_h2}}"

if [[ ! -x "$bin" ]]; then
  echo "test binary not found/executable: $bin" >&2
  echo "build it first: cmake --build <builddir> --target test_kernel_threaded_h2" >&2
  exit 2
fi

srv_out="$(mktemp)"
python3 "$here/test_h2c_server.py" >"$srv_out" 2>&1 &
srv_pid=$!
cleanup() { kill "$srv_pid" 2>/dev/null || true; rm -f "$srv_out"; }
trap cleanup EXIT

port=""
for _ in $(seq 1 100); do
  port="$(sed -n 's/^PORT //p' "$srv_out" 2>/dev/null | head -1)"
  [[ -n "$port" ]] && break
  sleep 0.05
done
if [[ -z "$port" ]]; then
  echo "h2c server failed to start:" >&2
  cat "$srv_out" >&2
  exit 1
fi

echo "h2c server pid=$srv_pid port=$port"
H2_TEST_PORT="$port" "$bin"
