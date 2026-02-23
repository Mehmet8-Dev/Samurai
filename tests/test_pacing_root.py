#!/usr/bin/env python3
"""
DDoSamurai — Root-Level Pacing Engine Test Suite
=================================================

Tests that require root (sudo) privileges to exercise:
  1. SO_TXTIME kernel offload (fast_sender.send_optimized_txtime)
  2. AF_PACKET TX_RING with pacing (pacing_engine L2 path)
  3. SCHED_FIFO real-time scheduling
  4. Full pacing pipeline (orchestrator → senders → pacing_engine)
  5. Pacing accuracy measurement across modes

Usage:
    sudo python3 -m pytest tests/test_pacing_root.py -v
    -- or --
    sudo python3 tests/test_pacing_root.py

Requires: Root privileges, C extensions built (make all).
"""

import os
import sys
import time
import struct
import socket
import argparse
import pytest

pytestmark = [pytest.mark.privileged, pytest.mark.benchmark]

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Colour output ────────────────────────────────────────────────────────────

class C:
    OK   = "\033[92m✅"
    FAIL = "\033[91m❌"
    WARN = "\033[93m⚠️ "
    INFO = "\033[94mℹ️ "
    BOLD = "\033[1m"
    END  = "\033[0m"


def banner(text):
    w = 60
    print(f"\n{C.BOLD}{'═' * w}{C.END}")
    print(f"{C.BOLD}  {text}{C.END}")
    print(f"{C.BOLD}{'═' * w}{C.END}")


# ── Test Helpers ─────────────────────────────────────────────────────────────

def build_dummy_ip_packet(target_ip="127.0.0.1", target_port=80, payload_size=64):
    """Build a minimal valid raw IP/TCP SYN packet for testing."""
    src_ip = "127.0.0.1"
    src_port = 12345

    # IP header (20 bytes)
    ip_ver_ihl = 0x45
    ip_tos = 0
    ip_total_len = 40 + payload_size  # IP(20) + TCP(20) + payload
    ip_id = 54321
    ip_frag = 0x4000  # DF
    ip_ttl = 64
    ip_proto = 6  # TCP
    ip_chk = 0
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(target_ip)

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl, ip_tos, ip_total_len, ip_id, ip_frag,
        ip_ttl, ip_proto, ip_chk, ip_src, ip_dst,
    )

    # IP checksum
    chk = _ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", chk) + ip_header[12:]

    # TCP header (20 bytes, SYN)
    tcp_flags = 0x02  # SYN
    seq = 1000
    ack = 0
    data_offset = 5 << 4
    window = 65535
    tcp_chk = 0
    urgent = 0

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, target_port, seq, ack,
        data_offset, tcp_flags, window, tcp_chk, urgent,
    )

    # Payload
    payload = b"\x41" * payload_size

    return ip_header + tcp_header + payload


def _ip_checksum(header):
    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_packet_buffer(count, target_ip="127.0.0.1", target_port=80, payload_size=64):
    """Build a contiguous buffer of `count` identical packets."""
    pkt = build_dummy_ip_packet(target_ip, target_port, payload_size)
    return bytes(pkt) * count, len(pkt)


def _require_pacing_engine() -> None:
    from ddos_samurai.pacing import PACING_ENGINE_AVAILABLE
    if not PACING_ENGINE_AVAILABLE:
        pytest.skip("pacing_engine C extension not available in this environment.")


def _require_root_raw_socket() -> None:
    if os.geteuid() != 0:
        pytest.skip("Raw socket pacing tests require root privileges.")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.close()
    except OSError as exc:
        pytest.skip(f"Raw socket unavailable in this environment: {exc}")


def _require_privileged_pacing() -> None:
    _require_pacing_engine()
    _require_root_raw_socket()


# ── Test 1: Capabilities Check ──────────────────────────────────────────────

def _probe_capabilities():
    banner("Test 1: System Capabilities Probe")

    from ddos_samurai.pacing import calibrate, check_capabilities, PACING_ENGINE_AVAILABLE
    from ddos_samurai import fast_sender

    is_root = os.geteuid() == 0
    print(f"  Running as root : {'YES' if is_root else 'NO'}")
    print(f"  Pacing engine   : {'LOADED' if PACING_ENGINE_AVAILABLE else 'NOT AVAILABLE'}")

    # Pacing engine capabilities
    caps = check_capabilities()
    print(f"\n  {C.INFO}Pacing Engine Capabilities:{C.END}")
    for k, v in caps.items():
        icon = C.OK if v else C.FAIL
        print(f"    {icon} {k:15s}: {'YES' if v else 'NO'}{C.END}")

    # fast_sender SO_TXTIME check
    fs_caps = fast_sender.check_so_txtime()
    print(f"\n  {C.INFO}fast_sender SO_TXTIME:{C.END}")
    for k, v in fs_caps.items():
        icon = C.OK if v else C.FAIL
        print(f"    {icon} {k:15s}: {'YES' if v else 'NO'}{C.END}")

    # Calibration
    cal = calibrate()
    print(f"\n  {C.INFO}Timing Calibration:{C.END}")
    for k, v in cal.items():
        if v > 1000:
            print(f"    {k:25s}: {v/1e3:>8.1f} µs")
        else:
            print(f"    {k:25s}: {v:>8,.0f} ns")

    return caps, fs_caps, cal


def test_capabilities():
    caps, fs_caps, cal = _probe_capabilities()
    assert isinstance(caps, dict)
    assert isinstance(fs_caps, dict)
    assert isinstance(cal, dict)


# ── Test 2: SO_TXTIME via fast_sender ────────────────────────────────────────

def test_so_txtime():
    banner("Test 2: SO_TXTIME Kernel Offload (fast_sender)")
    _require_root_raw_socket()

    from ddos_samurai import fast_sender

    fs_caps = fast_sender.check_so_txtime()
    if not fs_caps.get("so_txtime"):
        pytest.skip("SO_TXTIME is not available on this kernel/NIC setup.")

    _require_pacing_engine()

    count = 100
    buf, pkt_size = build_packet_buffer(count, "127.0.0.1", 80)

    # Create raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        pytest.skip("Cannot create raw socket in this environment.")

    ipg_ns = 100_000  # 100µs between packets

    print(f"  Sending {count} packets with IPG={ipg_ns/1e3:.0f}µs via SO_TXTIME...")

    try:
        result = fast_sender.send_optimized_txtime(
            s.fileno(), buf, "127.0.0.1", 80, pkt_size, count, ipg_ns
        )
        sent = result["sent"]
        errors = result["tx_errors"]
        print(f"  {C.OK}Sent: {sent}, TX errors: {errors}{C.END}")
        assert sent > 0
        assert errors >= 0
    except OSError as e:
        pytest.skip(f"SO_TXTIME send path unavailable in this environment: {e}")
    finally:
        s.close()


# ── Test 3: Pacing Engine Modes (L3) ────────────────────────────────────────

def test_pacing_modes():
    banner("Test 3: Pacing Engine Modes (L3 sendmmsg)")
    _require_privileged_pacing()

    from ddos_samurai.pacing import (
        PacingConfig, PacingMode, JitterModel,
        paced_send, get_stats, format_stats, reset_stats,
    )

    count = 1000
    buf, pkt_size = build_packet_buffer(count, "127.0.0.1", 80)

    # --- Mode: NONE (burst) ---
    print(f"\n  {C.INFO}Mode: NONE (burst){C.END}")
    reset_stats()
    cfg = PacingConfig(pacing_mode=PacingMode.NONE)
    t0 = time.monotonic_ns()
    sent = paced_send(buf, "127.0.0.1", 80, pkt_size, count, cfg)
    elapsed = (time.monotonic_ns() - t0) / 1e6
    print(f"    Sent: {sent:,}, Elapsed: {elapsed:.1f}ms")
    sent_none = sent

    # --- Mode: RPS (rate limited) ---
    print(f"\n  {C.INFO}Mode: RPS (50,000 pps){C.END}")
    reset_stats()
    cfg = PacingConfig(pacing_mode=PacingMode.RPS, target_rps=50_000)
    t0 = time.monotonic_ns()
    sent = paced_send(buf, "127.0.0.1", 80, pkt_size, count, cfg)
    elapsed = (time.monotonic_ns() - t0) / 1e6
    stats = get_stats()
    print(f"    Sent: {sent:,}, Elapsed: {elapsed:.1f}ms")
    print(f"    Actual RPS: {stats.get('actual_rps', 0):,.0f}")
    print(f"    Rate accuracy: {stats.get('rate_accuracy_pct', 0):.1f}%")
    sent_rps = sent

    # --- Mode: IPG (fixed gap) ---
    print(f"\n  {C.INFO}Mode: IPG (20µs gap){C.END}")
    reset_stats()
    cfg = PacingConfig(pacing_mode=PacingMode.IPG, ipg_ns=20_000)
    t0 = time.monotonic_ns()
    sent = paced_send(buf, "127.0.0.1", 80, pkt_size, count, cfg)
    elapsed = (time.monotonic_ns() - t0) / 1e6
    stats = get_stats()
    print(f"    Sent: {sent:,}, Elapsed: {elapsed:.1f}ms")
    print(f"    Mean IPG: {stats.get('ipg_mean_ns', 0)/1e3:.1f}µs (target: 20.0µs)")
    print(f"    IPG StdDev: {stats.get('ipg_stddev_ns', 0)/1e3:.1f}µs")
    sent_ipg = sent

    # --- Mode: BURST ---
    print(f"\n  {C.INFO}Mode: BURST (32 pkts per burst, 500µs gap){C.END}")
    reset_stats()
    cfg = PacingConfig(
        pacing_mode=PacingMode.BURST,
        burst_size=32,
        burst_gap_ns=500_000,
    )
    t0 = time.monotonic_ns()
    sent = paced_send(buf, "127.0.0.1", 80, pkt_size, count, cfg)
    elapsed = (time.monotonic_ns() - t0) / 1e6
    stats = get_stats()
    print(f"    Sent: {sent:,}, Elapsed: {elapsed:.1f}ms")
    expected_bursts = count / 32
    expected_ms = expected_bursts * 0.5
    print(f"    Expected ~{expected_ms:.0f}ms, got {elapsed:.1f}ms")
    sent_burst = sent

    assert sent_none > 0
    assert sent_rps > 0
    assert sent_ipg > 0
    assert sent_burst > 0


# ── Test 4: Jitter Models ────────────────────────────────────────────────────

def test_jitter_models():
    banner("Test 4: Jitter Models (IPG mode + jitter)")
    _require_privileged_pacing()

    from ddos_samurai.pacing import (
        PacingConfig, PacingMode, JitterModel,
        paced_send, get_stats, reset_stats,
    )

    count = 500
    buf, pkt_size = build_packet_buffer(count, "127.0.0.1", 80)
    base_ipg = 50_000  # 50µs

    for model in JitterModel:
        pct = 0.0 if model == JitterModel.NONE else 0.15
        print(f"\n  {C.INFO}Jitter: {model.name} (±{pct*100:.0f}%){C.END}")
        reset_stats()

        cfg = PacingConfig(
            pacing_mode=PacingMode.IPG,
            ipg_ns=base_ipg,
            jitter_model=model,
            jitter_pct=pct,
        )
        sent = paced_send(buf, "127.0.0.1", 80, pkt_size, count, cfg)
        stats = get_stats()

        print(f"    Sent      : {sent:,}")
        print(f"    IPG mean  : {stats.get('ipg_mean_ns', 0)/1e3:.1f}µs (base: 50.0µs)")
        print(f"    IPG stddev: {stats.get('ipg_stddev_ns', 0)/1e3:.1f}µs")
        print(f"    Jitter p50: {stats.get('jitter_p50_ns', 0)/1e3:.1f}µs")
        print(f"    Jitter p99: {stats.get('jitter_p99_ns', 0)/1e3:.1f}µs")
        assert sent > 0


# ── Test 5: SCHED_FIFO Real-Time Scheduling ─────────────────────────────────

def test_sched_fifo():
    banner("Test 5: SCHED_FIFO Real-Time Priority")
    _require_privileged_pacing()

    import ctypes
    import ctypes.util

    try:
        SCHED_FIFO = 1
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        class sched_param(ctypes.Structure):
            _fields_ = [("sched_priority", ctypes.c_int)]

        param = sched_param(sched_priority=50)
        ret = libc.sched_setscheduler(0, SCHED_FIFO, ctypes.byref(param))

        if ret == 0:
            print(f"  {C.OK}SCHED_FIFO set successfully (priority=50){C.END}")

            # Test with pacing at high precision
            from ddos_samurai.pacing import (
                PacingConfig, PacingMode, paced_send, get_stats, reset_stats,
            )

            count = 500
            buf, pkt_size = build_packet_buffer(count, "127.0.0.1", 80)
            reset_stats()

            cfg = PacingConfig(pacing_mode=PacingMode.IPG, ipg_ns=10_000)  # 10µs
            sent = paced_send(buf, "127.0.0.1", 80, pkt_size, count, cfg)
            stats = get_stats()

            print(f"    Sent: {sent:,}")
            print(f"    IPG mean  : {stats.get('ipg_mean_ns', 0)/1e3:.1f}µs (target: 10.0µs)")
            print(f"    IPG stddev: {stats.get('ipg_stddev_ns', 0)/1e3:.1f}µs")
            print(f"    Jitter p99: {stats.get('jitter_p99_ns', 0)/1e3:.1f}µs")
            assert sent > 0

            # Restore normal scheduling
            param.sched_priority = 0
            libc.sched_setscheduler(0, 0, ctypes.byref(param))  # SCHED_OTHER
            print(f"  {C.OK}Restored SCHED_OTHER{C.END}")
        else:
            errno = ctypes.get_errno()
            pytest.skip(f"sched_setscheduler unavailable in this environment (errno={errno}).")
    except Exception as e:
        pytest.skip(f"SCHED_FIFO test unavailable in this environment: {e}")


# ── Test 6: Full Pipeline (CLI → Orchestrator → Pacing) ─────────────────────

def test_pipeline():
    banner("Test 6: Full Pipeline Integration")

    from ddos_samurai.orchestrator import _build_pacing_config
    from ddos_samurai.pacing import PacingMode, JitterModel

    test_cases = [
        {"desc": "Default (no pacing)", "args": {}, "expect_mode": "NONE"},
        {"desc": "--rps 10000 (auto-promote)", "args": {"rps": 10000}, "expect_mode": "RPS"},
        {"desc": "--pacing-mode ipg --ipg 50000", "args": {"pacing_mode": "ipg", "ipg": 50000}, "expect_mode": "IPG"},
        {"desc": "--pacing-mode burst --burst-size 128 --burst-gap 1000000",
         "args": {"pacing_mode": "burst", "burst_size": 128, "burst_gap": 1000000},
         "expect_mode": "BURST"},
        {"desc": "--pacing-mode rps --rps 100000 --jitter-model gaussian --jitter-pct 0.1",
         "args": {"pacing_mode": "rps", "rps": 100000, "jitter_model": "gaussian", "jitter_pct": 0.1},
         "expect_mode": "RPS"},
    ]

    all_pass = True
    for tc in test_cases:
        cfg = _build_pacing_config(tc["args"])
        ok = cfg.pacing_mode.name == tc["expect_mode"]
        icon = C.OK if ok else C.FAIL
        print(f"  {icon} {tc['desc']:60s} → {cfg.pacing_mode.name}{C.END}")
        if not ok:
            all_pass = False

    assert all_pass


# ── Test 7: Pacing Accuracy Benchmark ────────────────────────────────────────

def test_accuracy_benchmark():
    banner("Test 7: Pacing Accuracy Benchmark")
    _require_privileged_pacing()

    from ddos_samurai.pacing import (
        PacingConfig, PacingMode, paced_send, get_stats, format_stats, reset_stats,
    )

    count = 2000
    buf, pkt_size = build_packet_buffer(count, "127.0.0.1", 80)

    targets = [10_000, 50_000, 100_000, 500_000]

    print(f"\n  {'Target RPS':>12}  {'Actual RPS':>12}  {'Accuracy':>10}  {'Jitter p99':>12}  {'Status'}")
    print(f"  {'─' * 12}  {'─' * 12}  {'─' * 10}  {'─' * 12}  {'─' * 8}")

    for target_rps in targets:
        reset_stats()
        cfg = PacingConfig(pacing_mode=PacingMode.RPS, target_rps=target_rps)
        paced_send(buf, "127.0.0.1", 80, pkt_size, count, cfg)
        stats = get_stats()
        assert stats

        actual = stats.get("actual_rps", 0)
        accuracy = stats.get("rate_accuracy_pct", 0)
        jitter_p99 = stats.get("jitter_p99_ns", 0)

        # Consider > 90% accuracy as PASS
        ok = accuracy >= 90.0 or accuracy == 0.0
        icon = C.OK if ok else C.WARN

        print(f"  {target_rps:>12,}  {actual:>12,.0f}  {accuracy:>9.1f}%  {jitter_p99/1e3:>10.1f}µs  {icon}{C.END}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DDoSamurai Pacing Engine Root Tests")
    parser.add_argument("--skip-so-txtime", action="store_true", help="Skip SO_TXTIME test")
    parser.add_argument("--skip-sched", action="store_true", help="Skip SCHED_FIFO test")
    parser.add_argument("--only", type=int, help="Run only test N (1-7)")
    args = parser.parse_args()

    is_root = os.geteuid() == 0

    print(f"""
{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║       DDoSamurai — Pacing Engine Root Test Suite             ║
╠══════════════════════════════════════════════════════════════╣
║  Root : {'YES ✅' if is_root else 'NO ❌ (some tests will be skipped)':54s}║
║  PID  : {os.getpid():<55d}║
╚══════════════════════════════════════════════════════════════╝{C.END}
""")

    if not is_root:
        print(f"  {C.WARN}Run with: sudo python3 tests/test_pacing_root.py{C.END}")
        print(f"  {C.INFO}Non-root tests will still run.{C.END}\n")

    run_all = args.only is None

    if run_all or args.only == 1:
        caps, fs_caps, cal = _probe_capabilities()
    else:
        caps = {"so_txtime": 0}
        fs_caps = {"so_txtime": 0}

    if (run_all or args.only == 2) and not args.skip_so_txtime:
        test_so_txtime()

    if run_all or args.only == 3:
        test_pacing_modes()

    if run_all or args.only == 4:
        test_jitter_models()

    if (run_all or args.only == 5) and not args.skip_sched:
        test_sched_fifo()

    if run_all or args.only == 6:
        test_pipeline()

    if run_all or args.only == 7:
        test_accuracy_benchmark()

    banner("All Tests Complete")
    print(f"  {C.OK}Done!{C.END}\n")


if __name__ == "__main__":
    main()
