#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

STRICT=1
if [[ "${1:-}" == "--report-only" ]]; then
  STRICT=0
elif [[ "${1:-}" == "--strict" ]]; then
  STRICT=1
elif [[ -n "${1:-}" ]]; then
  echo "[dpdk-check] unknown arg: $1" >&2
  echo "usage: $0 [--strict|--report-only]" >&2
  exit 2
fi

BLOCKERS=0
WARNINGS=0

ok() {
  echo "[OK] $*"
}

warn() {
  echo "[WARN] $*"
  WARNINGS=$((WARNINGS + 1))
}

block() {
  echo "[BLOCKER] $*"
  BLOCKERS=$((BLOCKERS + 1))
}

section() {
  echo
  echo "== $* =="
}

cmd_exists() {
  command -v "$1" >/dev/null 2>&1
}

get_nr_hugepages() {
  if [[ -r /proc/sys/vm/nr_hugepages ]]; then
    cat /proc/sys/vm/nr_hugepages
    return 0
  fi
  echo "0"
}

section "Host Basics"
echo "[info] repo: $ROOT_DIR"
echo "[info] kernel: $(uname -r)"

if cmd_exists python3; then
  ok "python3 found: $(python3 --version 2>/dev/null)"
else
  block "python3 not found"
fi

if cmd_exists gcc; then
  ok "gcc found: $(gcc --version 2>/dev/null | head -1)"
elif cmd_exists cc; then
  warn "gcc not found, cc found: $(cc --version 2>/dev/null | head -1)"
else
  block "no C compiler found (gcc/cc)"
fi

section "DPDK Build Deps"
DPDK_PKG=""
if cmd_exists pkg-config; then
  if pkg-config --exists libdpdk >/dev/null 2>&1; then
    DPDK_PKG="libdpdk"
  elif pkg-config --exists dpdk >/dev/null 2>&1; then
    DPDK_PKG="dpdk"
  fi
else
  block "pkg-config not found"
fi

if [[ -n "$DPDK_PKG" ]]; then
  ok "pkg-config package found: $DPDK_PKG ($(pkg-config --modversion "$DPDK_PKG" 2>/dev/null))"
  if [[ -n "$(pkg-config --cflags "$DPDK_PKG" 2>/dev/null)" ]]; then
    ok "dpdk cflags available"
  else
    block "dpdk cflags unavailable via pkg-config"
  fi
  if [[ -n "$(pkg-config --libs "$DPDK_PKG" 2>/dev/null)" ]]; then
    ok "dpdk libs available"
  else
    block "dpdk libs unavailable via pkg-config"
  fi
else
  block "dpdk pkg-config package not found (libdpdk/dpdk)"
fi

if [[ -f /usr/include/rte_eal.h || -f /usr/local/include/rte_eal.h ]]; then
  ok "rte_eal.h header found"
else
  block "rte_eal.h header not found"
fi

section "DPDK Runtime Deps"
if cmd_exists dpdk-testpmd || cmd_exists testpmd; then
  BIN="$(command -v dpdk-testpmd 2>/dev/null || command -v testpmd 2>/dev/null)"
  ok "testpmd found: $BIN"
else
  warn "testpmd binary not found (optional but useful for validation)"
fi

NR_HUGEPAGES="$(get_nr_hugepages)"
if [[ "${NR_HUGEPAGES:-0}" =~ ^[0-9]+$ ]] && [[ "$NR_HUGEPAGES" -gt 0 ]]; then
  ok "nr_hugepages=$NR_HUGEPAGES"
else
  block "nr_hugepages is 0 (set hugepages for DPDK runtime)"
fi

if grep -q "hugetlbfs" /proc/mounts 2>/dev/null; then
  ok "hugetlbfs mount present"
else
  block "hugetlbfs mount missing (/dev/hugepages)"
fi

if cmd_exists lsmod && lsmod | grep -Eq '^vfio_pci|^vfio-pci|^vfio'; then
  ok "vfio module appears loaded"
else
  warn "vfio module not detected (may be required depending on NIC/driver mode)"
fi

if [[ -d /sys/kernel/iommu_groups ]]; then
  COUNT="$(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "${COUNT:-0}" =~ ^[0-9]+$ ]] && [[ "$COUNT" -gt 0 ]]; then
    ok "iommu groups detected: $COUNT"
  else
    warn "iommu group directory present but empty"
  fi
else
  warn "iommu groups not found (enable IOMMU in BIOS/kernel if needed)"
fi

section "Project Integration Check"
if [[ -f ddos_samurai/dpdk/dpdk_pmd_core.cpp ]]; then
  ok "dpdk source exists in repo"
else
  block "dpdk source missing in repo (ddos_samurai/dpdk/dpdk_pmd_core.cpp)"
fi

PY_OUT="$(PYTHONPATH=. python3 - <<'PY'
import importlib
import sys

try:
    mod = importlib.import_module("ddos_samurai.dpdk_pmd_core")
except Exception as exc:
    print(f"IMPORT_ERR:{type(exc).__name__}:{exc}")
    sys.exit(0)

print("IMPORT_OK")
probe = getattr(mod, "dpdk_available", None)
if not callable(probe):
    print("PROBE_MISSING")
    sys.exit(0)

try:
    out = dict(probe() or {})
except Exception as exc:
    print(f"PROBE_ERR:{type(exc).__name__}:{exc}")
    sys.exit(0)

print(f"PROBE_OK:{out}")
PY
)"

if grep -q "^IMPORT_OK" <<<"$PY_OUT"; then
  ok "python import: ddos_samurai.dpdk_pmd_core"
else
  block "python import failed: ${PY_OUT//$'\n'/ ; }"
fi

if grep -q "^PROBE_OK:" <<<"$PY_OUT"; then
  ok "dpdk_available probe callable"
elif grep -q "^PROBE_MISSING" <<<"$PY_OUT"; then
  block "dpdk_available() missing in module"
else
  warn "dpdk_available probe did not return success: ${PY_OUT//$'\n'/ ; }"
fi

section "Summary"
echo "[summary] blockers=$BLOCKERS warnings=$WARNINGS strict=$STRICT"

if [[ "$STRICT" -eq 1 && "$BLOCKERS" -gt 0 ]]; then
  echo "[result] NOT READY"
  exit 1
fi

if [[ "$BLOCKERS" -gt 0 ]]; then
  echo "[result] NOT READY (report-only mode)"
else
  echo "[result] READY"
fi

exit 0
