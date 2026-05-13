"""
Samurai — Deterministic Pacing Engine (Python Wrapper)
=========================================================

Thin Python interface around the C ``pacing_engine`` extension.
Provides enum-like constants, a ``PacingConfig`` dataclass for clean
parametrisation, and high-level ``paced_send()`` / ``paced_send_l2()``
wrappers that handle fallback when the C module is unavailable.

Usage::

    from ddos_samurai.pacing import PacingConfig, paced_send, get_stats

    cfg = PacingConfig(
        pacing_mode=PacingMode.RPS,
        target_rps=100_000,
        jitter_model=JitterModel.GAUSSIAN,
        jitter_pct=0.05,          # ±5 % of base IPG
    )
    sent = paced_send(buf, "192.168.1.1", 80, pkt_size, count, cfg)
    print(get_stats())
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Sequence

log = logging.getLogger(__name__)

_COMMON_SBIN_PATHS = (
    "/usr/sbin",
    "/sbin",
    "/usr/local/sbin",
    "/usr/bin",
    "/bin",
)


def _find_tool(name: str) -> Optional[str]:
    path = shutil.which(name)
    if path:
        return path
    for base in _COMMON_SBIN_PATHS:
        cand = os.path.join(base, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _run_cmd_capture(cmd: Sequence[str], timeout: float = 1.5) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(
            list(cmd),
            text=True,
            capture_output=True,
            check=False,
            timeout=float(timeout),
        )
        return int(cp.returncode), str(cp.stdout or ""), str(cp.stderr or "")
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as exc:
        return 127, "", str(exc)


def _parse_int_token(raw: str) -> int:
    try:
        return int(str(raw).strip())
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return 0


def _probe_etf_qdisc(iface: str) -> dict:
    out = {
        "tc_available": 0,
        "etf_qdisc_present": 0,
        "etf_offload": 0,
        "etf_clockid": "",
        "etf_delta_ns": 0,
        "etf_parent": "",
        "etf_probe_error": "",
        "etf_qdisc_raw": "",
    }
    tc_bin = _find_tool("tc")
    if not tc_bin:
        out["etf_probe_error"] = "tc_not_found"
        return out
    out["tc_available"] = 1

    rc, stdout, stderr = _run_cmd_capture([tc_bin, "qdisc", "show", "dev", str(iface).strip()], timeout=2.0)
    if rc != 0:
        out["etf_probe_error"] = f"tc_qdisc_show_failed:{rc}:{(stderr or stdout).strip()}"
        return out

    for raw_line in str(stdout).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "qdisc etf " not in f" {line} ":
            continue
        toks = line.split()
        out["etf_qdisc_present"] = 1
        out["etf_qdisc_raw"] = line
        out["etf_offload"] = 1 if "offload" in toks else 0
        if "clockid" in toks:
            idx = toks.index("clockid")
            if idx + 1 < len(toks):
                out["etf_clockid"] = toks[idx + 1]
        if "delta" in toks:
            idx = toks.index("delta")
            if idx + 1 < len(toks):
                out["etf_delta_ns"] = _parse_int_token(toks[idx + 1])
        if "parent" in toks:
            idx = toks.index("parent")
            if idx + 1 < len(toks):
                out["etf_parent"] = toks[idx + 1]
        elif "root" in toks:
            out["etf_parent"] = "root"
        break

    if out["etf_qdisc_present"] == 0:
        out["etf_probe_error"] = "etf_qdisc_not_found"
    return out


def _probe_ethtool_tstamp(iface: str) -> dict:
    out = {
        "ethtool_available": 0,
        "ethtool_tstamp_probe_error": "",
        "ethtool_hw_tx_timestamp": 0,
        "ethtool_tx_sched_timestamp": 0,
        "ethtool_hwtstamp_tx_on": 0,
    }
    ethtool_bin = _find_tool("ethtool")
    if not ethtool_bin:
        out["ethtool_tstamp_probe_error"] = "ethtool_not_found"
        return out
    out["ethtool_available"] = 1

    rc, stdout, stderr = _run_cmd_capture([ethtool_bin, "-T", str(iface).strip()], timeout=2.0)
    if rc != 0:
        out["ethtool_tstamp_probe_error"] = f"ethtool_tstamp_failed:{rc}:{(stderr or stdout).strip()}"
        return out

    text = str(stdout)
    lower = text.lower()
    out["ethtool_hw_tx_timestamp"] = int(
        ("hardware-transmit" in lower)
        or ("sof_timestamping_tx_hardware" in lower)
    )
    out["ethtool_tx_sched_timestamp"] = int(
        ("sof_timestamping_tx_sched" in lower)
        or ("tx-sched" in lower)
    )
    has_tx_modes = "hardware transmit timestamp modes" in lower
    has_on_mode = re.search(r"^\s*on\s*$", text, flags=re.MULTILINE) is not None
    out["ethtool_hwtstamp_tx_on"] = int(has_tx_modes and has_on_mode)
    return out

# ── Try importing the C extension ────────────────────────────────────────────

try:
    from . import pacing_engine as _eng          # type: ignore[attr-defined]
    PACING_ENGINE_AVAILABLE = True
except ImportError:
    _eng = None
    PACING_ENGINE_AVAILABLE = False
    log.warning(
        "pacing_engine C extension not found.  "
        "Build it with:  make pacing  (inside ddos_samurai/)"
    )

# ── Enums ────────────────────────────────────────────────────────────────────

class PacingMode(IntEnum):
    """Packet pacing strategy."""
    NONE  = 0   # Fire-and-forget burst
    RPS   = 1   # Token-bucket rate limit (packets / sec)
    IPG   = 2   # Fixed inter-packet gap (nanoseconds)
    BURST = 3   # burst_size packets → burst_gap_ns wait → repeat


class JitterModel(IntEnum):
    """Jitter distribution applied on top of the base gap."""
    NONE        = 0
    UNIFORM     = 1   # ±jitter_pct × base_gap
    GAUSSIAN    = 2   # N(0, σ = base_gap × jitter_pct / 3)
    EXPONENTIAL = 3   # Exp(λ) centred around 0


# ── Configuration ────────────────────────────────────────────────────────────

@dataclass
class PacingConfig:
    """All pacing parameters for a single send operation."""

    pacing_mode:    PacingMode  = PacingMode.NONE
    target_rps:     float       = 0.0        # packets / second
    ipg_ns:         int         = 0          # inter-packet gap (ns)
    burst_size:     int         = 1          # packets per burst
    burst_gap_ns:   int         = 0          # ns between bursts
    jitter_model:   JitterModel = JitterModel.NONE
    jitter_pct:     float       = 0.0        # 0.0 – 1.0
    pin_cpu:        int         = -1         # CPU core to pin (-1 = none)
    use_so_txtime:  bool        = False      # kernel SO_TXTIME offload

    def validate(self) -> None:
        if self.jitter_pct < 0.0 or self.jitter_pct > 1.0:
            raise ValueError("jitter_pct must be within [0.0, 1.0]")
        if self.burst_size < 1:
            raise ValueError("burst_size must be >= 1")
        if self.burst_gap_ns < 0:
            raise ValueError("burst_gap_ns must be >= 0")
        if self.pacing_mode == PacingMode.RPS and self.target_rps <= 0:
            raise ValueError("target_rps must be > 0 for RPS mode")
        if self.pacing_mode == PacingMode.IPG and self.ipg_ns <= 0:
            raise ValueError("ipg_ns must be > 0 for IPG mode")

    def as_kwargs(self) -> dict:
        """Return a dict suitable for ``pacing_engine.paced_send_*``."""
        self.validate()
        return dict(
            target_rps    = self.target_rps,
            ipg_ns        = self.ipg_ns,
            burst_size    = self.burst_size,
            burst_gap_ns  = self.burst_gap_ns,
            jitter_model  = int(self.jitter_model),
            jitter_pct    = self.jitter_pct,
            pacing_mode   = int(self.pacing_mode),
            pin_cpu       = self.pin_cpu,
            use_so_txtime = self.use_so_txtime,
        )


_PACER_STATS_DEFAULTS = {
    "total_packets": 0,
    "total_bytes": 0,
    "elapsed_ns": 0.0,
    "target_rps": 0.0,
    "actual_rps": 0.0,
    "rate_accuracy_pct": 0.0,
    "ipg_min_ns": 0,
    "ipg_max_ns": 0,
    "ipg_mean_ns": 0.0,
    "ipg_stddev_ns": 0.0,
    "jitter_min_ns": 0.0,
    "jitter_max_ns": 0.0,
    "jitter_mean_ns": 0.0,
    "jitter_stddev_ns": 0.0,
    "jitter_p50_ns": 0.0,
    "jitter_p95_ns": 0.0,
    "jitter_p99_ns": 0.0,
    "busywait_cycles": 0,
    "sleep_calls": 0,
    "so_txtime_active": 0,
    "txtime_errors": 0,
    "txring_flush_call_count": 0,
    "txring_flush_error_count": 0,
    "txring_flush_eagain_count": 0,
    "txring_flush_enobufs_count": 0,
    "txring_flush_ebusy_count": 0,
    "txring_flush_other_errno_count": 0,
    "txring_flush_last_errno": 0,
    "txring_flush_last_errno_name": "NONE",
    "txring_frame_wait_ns": 0,
    "txring_poll_count": 0,
    "txring_tp_packets": 0,
    "txring_tp_drops": 0,
    "txring_tp_freeze_q_cnt": 0,
    "txring_packet_version": 0,
    "txring_packet_version_name": "TPACKET_UNKNOWN",
    "afpacket_hugepage_mode": "off",
    "afpacket_hugepage_effective": 0,
    "afpacket_hugepage_reason": "disabled",
    "afpacket_hugepage_size_kb": 0,
    "afpacket_madvise_hugepage_ok": 0,
    "afpacket_mlock_ok": 0,
    "afpacket_prefault_pages": 0,
    "afpacket_smaps_kernel_page_kb": 0,
    "afpacket_smaps_anon_hugepages_kb": 0,
    "afpacket_ring_block_size": 0,
    "afpacket_ring_block_nr": 0,
    "afpacket_ring_size_bytes": 0,
    "xdp_mode_requested": 0,
    "xdp_mode_effective": 0,
    "xdp_mode2_policy": "soft",
    "xdp_mode2_probe_status": "not_run",
    "xdp_mode2_probe_reason": "not_run",
    "xdp_sender_fallback_reason_detail": "",
    "syscall_overhead_ns": 0,
    "sleep_overhead_ns": 0,
    "spin_threshold_ns": 0,
    "ipg_histogram": [],
}


def normalize_stats(stats: Optional[dict]) -> dict:
    out = dict(_PACER_STATS_DEFAULTS)
    raw = dict(stats or {})
    out.update(raw)
    # Ensure expected field types.
    out["so_txtime_active"] = int(bool(out.get("so_txtime_active", 0)))
    out["txring_flush_last_errno_name"] = str(out.get("txring_flush_last_errno_name", "NONE") or "NONE")
    out["txring_packet_version_name"] = str(out.get("txring_packet_version_name", "TPACKET_UNKNOWN") or "TPACKET_UNKNOWN")
    out["afpacket_hugepage_mode"] = str(out.get("afpacket_hugepage_mode", "off") or "off")
    out["afpacket_hugepage_reason"] = str(out.get("afpacket_hugepage_reason", "disabled") or "disabled")
    out["xdp_mode2_policy"] = str(out.get("xdp_mode2_policy", "soft") or "soft")
    out["xdp_mode2_probe_status"] = str(out.get("xdp_mode2_probe_status", "not_run") or "not_run")
    out["xdp_mode2_probe_reason"] = str(out.get("xdp_mode2_probe_reason", "not_run") or "not_run")
    out["xdp_sender_fallback_reason_detail"] = str(
        out.get("xdp_sender_fallback_reason_detail", "") or ""
    )
    hist = out.get("ipg_histogram")
    out["ipg_histogram"] = list(hist) if isinstance(hist, (list, tuple)) else []
    return out


# ── High-Level API ───────────────────────────────────────────────────────────

def paced_send(
    buffer: bytes,
    target_ip: str,
    target_port: int,
    packet_size: int,
    count: int,
    config: Optional[PacingConfig] = None,
) -> int:
    """
    Send *count* L3 packets with deterministic pacing.

    Falls back to a dumb ``sendmmsg`` loop if the C engine is missing.
    """
    if config is None:
        config = PacingConfig()
    config.validate()

    if not PACING_ENGINE_AVAILABLE:
        log.warning("Pacing engine unavailable — falling back to unpaced send")
        return _fallback_send(buffer, target_ip, target_port,
                              packet_size, count)

    return _eng.paced_send_l3(
        buffer, target_ip, target_port, packet_size, count,
        **config.as_kwargs(),
    )


def paced_send_l2(
    iface: str,
    buffer: bytes,
    packet_size: int,
    count: int,
    gateway_mac: bytes,
    config: Optional[PacingConfig] = None,
) -> int:
    """
    Send *count* L2 packets via AF_PACKET TX_RING with deterministic pacing.
    """
    if config is None:
        config = PacingConfig()
    config.validate()

    if not PACING_ENGINE_AVAILABLE:
        log.warning("Pacing engine unavailable — L2 paced send not possible")
        return 0

    kw = config.as_kwargs()
    kw.pop("use_so_txtime", None)   # L2 path doesn't use SO_TXTIME
    return _eng.paced_send_l2(
        iface, buffer, packet_size, count, gateway_mac,
        **kw,
    )


def paced_send_xdp(
    *args,
    config: Optional[PacingConfig] = None,
    iface: Optional[str] = None,
    queue_id: int = 0,
    xdp_mode: int = 0,
    xdp_mode2_policy: str = "soft",
) -> int:
    """
    Send *count* packets via AF_XDP with deterministic pacing.

    Notes:
        - Preferred call shape:
          ``paced_send_xdp(iface, buffer, packet_size, count, ...)``
        - Backward-compatible shape:
          ``paced_send_xdp(buffer, packet_size, count, ...)``
          (interface is then resolved from ``iface=...`` or env
          ``SAMURAI_XDP_INTERFACE``).
    """
    if len(args) == 4:
        iface_arg, buffer, packet_size, count = args
        if iface is None:
            iface = str(iface_arg or "")
    elif len(args) == 3:
        buffer, packet_size, count = args
    else:
        raise TypeError(
            "paced_send_xdp expects (iface, buffer, packet_size, count) "
            "or (buffer, packet_size, count)"
        )

    if config is None:
        config = PacingConfig()
    config.validate()

    if not PACING_ENGINE_AVAILABLE:
        log.warning("Pacing engine unavailable — XDP paced send not possible")
        return 0

    kw = config.as_kwargs()
    kw.pop("use_so_txtime", None)   # XDP path does not use SO_TXTIME

    iface_raw = str(iface or "").strip()
    if not iface_raw:
        iface_raw = str(os.environ.get("SAMURAI_XDP_INTERFACE", "") or "").strip()
    if not iface_raw:
        raise ValueError("iface is required for paced_send_xdp")

    kw.update(
        queue_id=int(queue_id or 0),
        xdp_mode=int(xdp_mode or 0),
        xdp_mode2_policy=str(xdp_mode2_policy or "soft"),
    )
    return _eng.paced_send_xdp(
        iface_raw,
        buffer,
        int(packet_size),
        int(count),
        **kw,
    )


# ── Statistics ───────────────────────────────────────────────────────────────

def get_stats() -> dict:
    """Retrieve pacing statistics from the last send operation."""
    if not PACING_ENGINE_AVAILABLE:
        return normalize_stats({})
    return normalize_stats(_eng.get_pacing_stats())


def reset_stats() -> None:
    """Reset all pacing counters / histograms."""
    if PACING_ENGINE_AVAILABLE:
        _eng.reset_pacing_stats()


def calibrate() -> dict:
    """
    Run timing calibration and return system characteristics.

    Returns dict with keys:
        syscall_overhead_ns  — clock_gettime() latency
        sleep_overhead_ns    — clock_nanosleep() wakeup overshoot
        spin_threshold_ns    — computed busy-wait→sleep crossover point
        tsc_supported        — invariant TSC support flag (0/1)
        tsc_enabled          — active timing source uses RDTSC (0/1)
        tsc_hz               — calibrated TSC frequency
        tsc_overhead_cycles  — rdtsc->rdtsc mean cycle cost
        timing_source        — "rdtsc" | "clock_gettime"
    """
    if not PACING_ENGINE_AVAILABLE:
        return {}
    cal = dict(_eng.calibrate() or {})
    # Keep calibration values visible in normalized schema as well.
    merged = normalize_stats(cal)
    return {
        "syscall_overhead_ns": int(merged.get("syscall_overhead_ns", 0) or 0),
        "sleep_overhead_ns": int(merged.get("sleep_overhead_ns", 0) or 0),
        "spin_threshold_ns": int(merged.get("spin_threshold_ns", 0) or 0),
        "tsc_supported": int(cal.get("tsc_supported", 0) or 0),
        "tsc_enabled": int(cal.get("tsc_enabled", 0) or 0),
        "tsc_hz": int(cal.get("tsc_hz", 0) or 0),
        "tsc_overhead_cycles": int(cal.get("tsc_overhead_cycles", 0) or 0),
        "timing_source": str(cal.get("timing_source", "clock_gettime") or "clock_gettime"),
    }


def check_capabilities(
    iface: Optional[str] = None,
    *,
    include_etf_probe: bool = True,
) -> dict:
    """
    Probe kernel capabilities relevant to pacing.

    Returns dict with bool-like keys:
        so_txtime, clock_tai, sched_fifo, af_packet, is_root,
        invariant_tsc, tsc_enabled, tsc_hz, timing_source
    Plus ETF-related keys (when ``include_etf_probe=True``):
        tc_available, etf_qdisc_present, etf_offload, etf_clockid,
        etf_delta_ns, etf_parent, ethtool_available, etf_ready.
    """
    caps = {}
    if PACING_ENGINE_AVAILABLE:
        caps = dict(_eng.check_capabilities() or {})

    out = {
        "pacing_engine_available": int(PACING_ENGINE_AVAILABLE),
        "so_txtime": int(caps.get("so_txtime", 0) or 0),
        "clock_tai": int(caps.get("clock_tai", 0) or 0),
        "sched_fifo": int(caps.get("sched_fifo", 0) or 0),
        "af_packet": int(caps.get("af_packet", 0) or 0),
        "tpacket_v3": int(caps.get("tpacket_v3", 0) or 0),
        "is_root": int(caps.get("is_root", int(os.geteuid() == 0)) or 0),
        "invariant_tsc": int(caps.get("invariant_tsc", 0) or 0),
        "tsc_enabled": int(caps.get("tsc_enabled", 0) or 0),
        "tsc_hz": int(caps.get("tsc_hz", 0) or 0),
        "timing_source": str(caps.get("timing_source", "clock_gettime") or "clock_gettime"),
    }

    resolved_iface = str(
        (iface or os.environ.get("SAMURAI_ETF_IFACE") or os.environ.get("SAMURAI_XDP_INTERFACE") or "")
    ).strip()
    out["etf_iface"] = resolved_iface

    if include_etf_probe:
        if resolved_iface:
            out.update(_probe_etf_qdisc(resolved_iface))
            out.update(_probe_ethtool_tstamp(resolved_iface))
            out["etf_ready"] = int(
                out.get("so_txtime", 0)
                and out.get("clock_tai", 0)
                and out.get("tc_available", 0)
                and out.get("etf_qdisc_present", 0)
                and str(out.get("etf_clockid", "")).upper() == "CLOCK_TAI"
            )
        else:
            out.update(
                {
                    "tc_available": int(_find_tool("tc") is not None),
                    "etf_qdisc_present": 0,
                    "etf_offload": 0,
                    "etf_clockid": "",
                    "etf_delta_ns": 0,
                    "etf_parent": "",
                    "etf_probe_error": "iface_missing",
                    "etf_qdisc_raw": "",
                    "ethtool_available": int(_find_tool("ethtool") is not None),
                    "ethtool_tstamp_probe_error": "iface_missing",
                    "ethtool_hw_tx_timestamp": 0,
                    "ethtool_tx_sched_timestamp": 0,
                    "ethtool_hwtstamp_tx_on": 0,
                    "etf_ready": 0,
                }
            )
    return out


def ensure_etf_qdisc(
    iface: str,
    *,
    delta_ns: int = 200_000,
    offload: bool = True,
    parent: str = "root",
    replace: bool = True,
    strict: bool = True,
    dry_run: bool = False,
) -> dict:
    """
    Configure ETF qdisc for SO_TXTIME pacing.

    Example:
        ensure_etf_qdisc("eth0", delta_ns=200_000, offload=True, parent="root")
    """
    iface_s = str(iface or "").strip()
    parent_s = str(parent or "root").strip()
    if not iface_s:
        raise ValueError("iface is required")
    if delta_ns <= 0:
        raise ValueError("delta_ns must be > 0")
    if not parent_s:
        raise ValueError("parent must be non-empty")

    tc_bin = _find_tool("tc")
    if not tc_bin:
        msg = "tc_not_found"
        if strict:
            raise RuntimeError(msg)
        return {"ok": 0, "error": msg, "iface": iface_s}

    action = "replace" if replace else "add"
    cmd = [tc_bin, "qdisc", action, "dev", iface_s]
    if parent_s.lower() == "root":
        cmd.append("root")
    else:
        cmd.extend(["parent", parent_s])
    cmd.extend(["etf", "clockid", "CLOCK_TAI", "delta", str(int(delta_ns))])
    if bool(offload):
        cmd.append("offload")

    out = {
        "ok": 0,
        "iface": iface_s,
        "parent": parent_s,
        "action": action,
        "offload_requested": int(bool(offload)),
        "delta_ns": int(delta_ns),
        "cmd": " ".join(cmd),
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "error": "",
    }
    if dry_run:
        out["ok"] = 1
        out["dry_run"] = 1
        return out

    rc, stdout, stderr = _run_cmd_capture(cmd, timeout=3.0)
    out["returncode"] = int(rc)
    out["stdout"] = stdout
    out["stderr"] = stderr
    if rc != 0:
        out["error"] = f"tc_etf_config_failed:{rc}:{(stderr or stdout).strip()}"
        if strict:
            raise RuntimeError(out["error"])
        return out

    probe = check_capabilities(iface=iface_s, include_etf_probe=True)
    out.update(
        {
            "etf_qdisc_present": int(probe.get("etf_qdisc_present", 0) or 0),
            "etf_offload": int(probe.get("etf_offload", 0) or 0),
            "etf_clockid": str(probe.get("etf_clockid", "") or ""),
            "etf_delta_ns": int(probe.get("etf_delta_ns", 0) or 0),
            "etf_ready": int(probe.get("etf_ready", 0) or 0),
            "etf_probe_error": str(probe.get("etf_probe_error", "") or ""),
        }
    )
    out["ok"] = int(out["etf_qdisc_present"] == 1 and out["etf_clockid"].upper() == "CLOCK_TAI")
    if bool(offload):
        out["ok"] = int(out["ok"] and int(out["etf_offload"]) == 1)
    if strict and not out["ok"]:
        raise RuntimeError(
            f"etf_verify_failed:present={out['etf_qdisc_present']} "
            f"clockid={out['etf_clockid']} offload={out['etf_offload']}"
        )
    return out


def remove_etf_qdisc(
    iface: str,
    *,
    parent: str = "root",
    strict: bool = False,
) -> dict:
    """
    Remove ETF qdisc from an interface path.
    """
    iface_s = str(iface or "").strip()
    parent_s = str(parent or "root").strip()
    if not iface_s:
        raise ValueError("iface is required")
    tc_bin = _find_tool("tc")
    if not tc_bin:
        msg = "tc_not_found"
        if strict:
            raise RuntimeError(msg)
        return {"ok": 0, "error": msg, "iface": iface_s}
    cmd = [tc_bin, "qdisc", "del", "dev", iface_s]
    if parent_s.lower() == "root":
        cmd.append("root")
    else:
        cmd.extend(["parent", parent_s])

    rc, stdout, stderr = _run_cmd_capture(cmd, timeout=2.0)
    out = {
        "ok": int(rc == 0),
        "iface": iface_s,
        "parent": parent_s,
        "cmd": " ".join(cmd),
        "returncode": int(rc),
        "stdout": stdout,
        "stderr": stderr,
        "error": "" if rc == 0 else f"tc_etf_delete_failed:{rc}:{(stderr or stdout).strip()}",
    }
    if strict and rc != 0:
        raise RuntimeError(out["error"])
    return out


def cleanup_l2() -> None:
    """Release persistent TX_RING mmap resources (L2 sender)."""
    if PACING_ENGINE_AVAILABLE:
        _eng.cleanup_l2_ring()


# ── Pretty-Print ─────────────────────────────────────────────────────────────

def format_stats(stats: Optional[dict] = None, *, indent: int = 2) -> str:
    """Human-readable summary of pacing statistics."""
    if stats is None:
        stats = get_stats()
    if not stats:
        return "(no pacing statistics available)"

    pad = " " * indent
    lines = []
    a = lines.append

    a(f"{pad}═══ Pacing Statistics ═══")
    a(f"{pad}Packets sent : {stats.get('total_packets', 0):,}")
    a(f"{pad}Bytes sent   : {stats.get('total_bytes', 0):,}")
    elapsed_ms = stats.get('elapsed_ns', 0) / 1e6
    a(f"{pad}Elapsed      : {elapsed_ms:,.2f} ms")
    a(f"{pad}Target RPS   : {stats.get('target_rps', 0):,.0f}")
    a(f"{pad}Actual RPS   : {stats.get('actual_rps', 0):,.0f}")
    a(f"{pad}Rate accuracy: {stats.get('rate_accuracy_pct', 0):.2f} %")
    a("")

    a(f"{pad}── Inter-Packet Gap ──")
    a(f"{pad}  Min    : {stats.get('ipg_min_ns', 0):>10,} ns   ({stats.get('ipg_min_ns', 0) / 1e3:>8.1f} µs)")
    a(f"{pad}  Max    : {stats.get('ipg_max_ns', 0):>10,} ns   ({stats.get('ipg_max_ns', 0) / 1e3:>8.1f} µs)")
    a(f"{pad}  Mean   : {stats.get('ipg_mean_ns', 0):>10,.0f} ns   ({stats.get('ipg_mean_ns', 0) / 1e3:>8.1f} µs)")
    a(f"{pad}  StdDev : {stats.get('ipg_stddev_ns', 0):>10,.0f} ns   ({stats.get('ipg_stddev_ns', 0) / 1e3:>8.1f} µs)")
    a("")

    a(f"{pad}── Jitter (|actual - intended|) ──")
    a(f"{pad}  Min    : {stats.get('jitter_min_ns', 0):>10,.0f} ns")
    a(f"{pad}  Max    : {stats.get('jitter_max_ns', 0):>10,.0f} ns")
    a(f"{pad}  Mean   : {stats.get('jitter_mean_ns', 0):>10,.0f} ns")
    a(f"{pad}  StdDev : {stats.get('jitter_stddev_ns', 0):>10,.0f} ns")
    a(f"{pad}  P50    : {stats.get('jitter_p50_ns', 0):>10,.0f} ns")
    a(f"{pad}  P95    : {stats.get('jitter_p95_ns', 0):>10,.0f} ns")
    a(f"{pad}  P99    : {stats.get('jitter_p99_ns', 0):>10,.0f} ns")
    a("")

    a(f"{pad}── Wait Strategy ──")
    a(f"{pad}  Busy-wait iters : {stats.get('busywait_cycles', 0):,}")
    a(f"{pad}  Sleep calls     : {stats.get('sleep_calls', 0):,}")
    a(f"{pad}  Spin threshold  : {stats.get('spin_threshold_ns', 0):,} ns")
    a("")

    a(f"{pad}── Calibration ──")
    a(f"{pad}  clock_gettime() : {stats.get('syscall_overhead_ns', 0):,} ns")
    a(f"{pad}  nanosleep wake  : {stats.get('sleep_overhead_ns', 0):,} ns")
    a(f"{pad}  SO_TXTIME       : {'active' if stats.get('so_txtime_active') else 'not used'}")
    if stats.get('txtime_errors', 0):
        a(f"{pad}  TXTIME errors   : {stats['txtime_errors']:,}")

    return "\n".join(lines)


# ── Fallback (no C extension) ────────────────────────────────────────────────

def _fallback_send(buffer, target_ip, target_port, packet_size, count):
    """Dumb Python raw-socket sender — no pacing, used only as last resort."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        log.error("Raw socket requires root privileges.")
        return 0

    mv = memoryview(buffer)
    sent = 0
    for i in range(count):
        start = i * packet_size
        end   = start + packet_size
        try:
            s.sendto(mv[start:end], (target_ip, target_port))
            sent += 1
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            break
    s.close()
    return sent
