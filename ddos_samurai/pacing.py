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
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

log = logging.getLogger(__name__)

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


def check_capabilities() -> dict:
    """
    Probe kernel capabilities relevant to pacing.

    Returns dict with bool-like keys:
        so_txtime, clock_tai, sched_fifo, af_packet, is_root,
        invariant_tsc, tsc_enabled, tsc_hz, timing_source
    """
    if not PACING_ENGINE_AVAILABLE:
        return {}
    return _eng.check_capabilities()


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
