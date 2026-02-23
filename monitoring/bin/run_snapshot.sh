#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${1:-}"
if [[ -z "${RUN_ID}" ]]; then
  echo "usage: $0 <run_id> [--ethtool <iface>]"
  exit 2
fi

shift || true
ETH_IFACE=""
if [[ "${1:-}" == "--ethtool" ]]; then
  ETH_IFACE="${2:-}"
  if [[ -z "${ETH_IFACE}" ]]; then
    echo "error: --ethtool requires an interface name"
    exit 2
  fi
fi

BASE_DIR="reports/telemetry/${RUN_ID}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${BASE_DIR}/${TS}"
mkdir -p "${OUT_DIR}"

{
  echo "timestamp_utc=${TS}"
  echo "uname=$(uname -a)"
  echo "cwd=$(pwd)"
} > "${OUT_DIR}/meta.txt"

command -v uptime >/dev/null 2>&1 && uptime > "${OUT_DIR}/uptime.txt" || true
command -v free >/dev/null 2>&1 && free -h > "${OUT_DIR}/free.txt" || true
command -v vmstat >/dev/null 2>&1 && vmstat 1 5 > "${OUT_DIR}/vmstat_1s_5.txt" || true
command -v mpstat >/dev/null 2>&1 && mpstat -P ALL 1 3 > "${OUT_DIR}/mpstat_1s_3.txt" || true
command -v iostat >/dev/null 2>&1 && iostat -x 1 3 > "${OUT_DIR}/iostat_x_1s_3.txt" || true

command -v ip >/dev/null 2>&1 && ip -s link > "${OUT_DIR}/ip_s_link.txt" || true
command -v ss >/dev/null 2>&1 && ss -s > "${OUT_DIR}/ss_s.txt" || true
command -v nstat >/dev/null 2>&1 && nstat -az > "${OUT_DIR}/nstat_az.txt" || true

if [[ -r /proc/net/softnet_stat ]]; then
  cp /proc/net/softnet_stat "${OUT_DIR}/proc_net_softnet_stat.txt"
fi

if [[ -r /proc/net/dev ]]; then
  cp /proc/net/dev "${OUT_DIR}/proc_net_dev.txt"
fi

if [[ -n "${ETH_IFACE}" ]]; then
  if command -v ethtool >/dev/null 2>&1; then
    # ethtool stats often require root depending on driver.
    ethtool -S "${ETH_IFACE}" > "${OUT_DIR}/ethtool_S_${ETH_IFACE}.txt" 2>&1 || true
    ethtool "${ETH_IFACE}" > "${OUT_DIR}/ethtool_${ETH_IFACE}.txt" 2>&1 || true
  else
    echo "ethtool not found" > "${OUT_DIR}/ethtool_missing.txt"
  fi
fi

echo "snapshot_written=${OUT_DIR}"

