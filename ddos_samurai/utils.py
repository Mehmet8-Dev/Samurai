import time
from datetime import datetime
import ipaddress
import logging
import shutil
import sys
from textwrap import dedent

RESET = "\033[0m"
DIM = "\033[90m"
WHITE = "\033[37m"
ACCENT = "\033[97m"
MUTED = "\033[90m"


def _color(text: str, style: str) -> str:
    return f"{style}{text}{RESET}"


def _term_width() -> int:
    return shutil.get_terminal_size((80, 20)).columns


def _center(text: str) -> str:
    return "\n".join(line.center(_term_width()) for line in str(text).splitlines())


def _clear_screen():
    print("\033[2J\033[H", end="")

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _write_python_log(level: int, message: str):
    # Avoid Python's fallback "CRITICAL:root:..." stderr echo before the CLI
    # configures logging; once configured, keep writing to the selected log sink.
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.log(level, message)

def log_info(msg, protocol=None):
    timestamp = get_timestamp()
    proto_str = f" [{protocol.upper()}]" if protocol else ""
    print(f"{_color(f'[{timestamp}]', DIM)} {_color('●', ACCENT)} {_color(f'{msg}{proto_str}', WHITE)}")
    _write_python_log(logging.INFO, f"[{timestamp}] [INFO]{' (' + protocol.upper() + ')' if protocol else ''} {msg}")

def log_warning(msg):
    timestamp = get_timestamp()
    print(f"{_color(f'[{timestamp}]', DIM)} {_color('⚠', ACCENT)}  {_color(str(msg), WHITE)}")
    _write_python_log(logging.WARNING, f"[{timestamp}] [WARNING] {msg}")

def log_error(msg):
    timestamp = get_timestamp()
    print(f"{_color(f'[{timestamp}]', DIM)} {_color('✗', ACCENT)}  {_color(str(msg), ACCENT)}")
    _write_python_log(logging.ERROR, f"[{timestamp}] [ERROR] {msg}")

def log_critical(msg):
    timestamp = get_timestamp()
    print(f"{_color(f'[{timestamp}]', DIM)} {_color('▲', ACCENT)}  {_color(str(msg), ACCENT)}")
    _write_python_log(logging.CRITICAL, f"[{timestamp}] [CRITICAL] {msg}")

def print_banner():
    """
    Samurai banner'ini terminal'de gosterir.
    Siyah/kirmizi odakli terminal tasarimi.
    """
    _clear_screen()

    banner = dedent(r"""
        ███████╗ █████╗ ███╗   ███╗██╗   ██╗██████╗  █████╗ ██╗
        ██╔════╝██╔══██╗████╗ ████║██║   ██║██╔══██╗██╔══██╗██║
        ███████╗███████║██╔████╔██║██║   ██║██████╔╝███████║██║
        ╚════██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║██║
        ███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██║
        ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
    """).strip("\n")

    print(_color(_center("Samurai"), ACCENT))
    print(_color(_center(banner), ACCENT))
    print()

def print_system_status(args):
    """
    Sistem durumunu ve saldırı parametrelerini gösterir.
    Siyah zemin ve kirmizi vurgu temasi kullanilir.
    """
    gpu_status = "AKTİF (CUDA)" if 'cupy' in sys.modules else "HAZIR (CPU)"
    stealth_status = "AÇIK" if bool(getattr(args, "stealth_mode", False)) else "KAPALI"
    rows = [
        ("GPU", gpu_status),
        ("WORKERS", str(args.workers)),
        ("PROTOCOL", str(args.protocol).upper()),
        ("TARGET", f"{args.target}:{args.port}"),
        ("VECTOR", str(args.attack_vector).upper()),
        ("STEALTH", stealth_status),
    ]

    key_w = 18
    val_w = min(46, max(len(v) for _, v in rows) + 2)
    width = key_w + val_w + 7
    lines = [
        _color("─" * width, DIM),
        _color("SİSTEM BİLGİLERİ".center(width), ACCENT),
        _color("─" * width, DIM),
    ]
    for key, value in rows:
        lines.append(
            f"{_color(key.rjust(key_w), DIM)}  "
            f"{_color('│', DIM)}  "
            f"{_color(value.ljust(val_w), ACCENT if key in {'WORKERS', 'TARGET', 'STEALTH'} else WHITE)}"
        )
    lines.extend([
        _color("─" * width, DIM),
        _color(f"{get_timestamp()}  workers={args.workers}".center(width), DIM),
    ])

    print(_center("\n".join(lines)))
    print()


def attack_live_monitor(
    processes,
    progress,
    lock,
    total_count,
    refresh: float = 0.25,
    sent_total=None,
    errors_total=None,
    resource_stats=None,
    soak_config=None,
    auto_abort_on_alarm: bool = False,
):
    """
    Saldırı ilerlemesini izler ve güncellemeleri loglar.
    Minimalist, profesyonel tasarım.
    """
    from .live_metrics import LiveMetricsExporter
    exporter = LiveMetricsExporter()
    
    start = time.time()
    last_print_time = 0.0
    last_total = -1
    last_sent_for_inst = 0
    last_inst_time = start

    soak_enabled = bool(soak_config)
    has_total_target = int(total_count or 0) > 0
    soak_snapshots = []
    soak_alarms = []
    soak_alarm_codes = set()
    abort_triggered = False
    soak_baseline = None
    soak_baseline_pps = 0.0
    soak_baseline_source_count = 0
    soak_warmup_samples = []
    soak_next_snapshot = start
    soak_interval = int((soak_config or {}).get("snapshot_interval_s", 10) or 10)
    soak_interval = max(10, min(30, soak_interval))
    soak_warmup_s = max(0.0, float((soak_config or {}).get("warmup_s", 60) or 0.0))
    thresholds = {
        "max_error_rate_pct": float((soak_config or {}).get("max_error_rate_pct", 100.0) or 100.0),
        "max_pps_drop_pct": float((soak_config or {}).get("max_pps_drop_pct", 100.0) or 100.0),
        "max_rss_growth_mb": float((soak_config or {}).get("max_rss_growth_mb", 0.0) or 0.0),
        "max_vram_growth_mb": float((soak_config or {}).get("max_vram_growth_mb", 0.0) or 0.0),
        "max_pinned_growth_mb": float((soak_config or {}).get("max_pinned_growth_mb", 0.0) or 0.0),
        "max_backlog": int((soak_config or {}).get("max_backlog", 0) or 0),
        "required_duration_s": int((soak_config or {}).get("duration_s", 0) or 0),
        "warmup_s": float(soak_warmup_s),
    }
    ai_samples = []
    ai_last_sample_ts = start
    ai_prev_timeout_total = 0.0

    def _bytes_to_mb(v: int) -> float:
        return float(v) / (1024.0 * 1024.0)

    def _emit_alarm(code: str, message: str, value=None, threshold=None):
        nonlocal abort_triggered
        if code in soak_alarm_codes:
            return
        soak_alarm_codes.add(code)
        alarm = {"code": str(code), "message": str(message)}
        if value is not None:
            alarm["value"] = float(value)
        if threshold is not None:
            alarm["threshold"] = float(threshold)
        soak_alarms.append(alarm)
        log_warning(f"[SOAK] {message}")
        if bool(auto_abort_on_alarm):
            abort_triggered = True

    try:
        while any(p.is_alive() for p in processes):
            now = time.time()
            elapsed = now - start

            # Read shared progress safely (coarse-grained).
            p_val = 0
            s_val = 0
            e_val = 0
            try:
                if lock:
                    with lock:
                        p_val = int(getattr(progress, "value", 0) or 0)
                        s_val = int(getattr(sent_total, "value", 0) or 0) if sent_total else p_val
                        e_val = int(getattr(errors_total, "value", 0) or 0) if errors_total else 0
                else:
                    p_val = int(getattr(progress, "value", 0) or 0)
                    s_val = int(getattr(sent_total, "value", 0) or 0) if sent_total else p_val
                    e_val = int(getattr(errors_total, "value", 0) or 0) if errors_total else 0
            except (AttributeError, TypeError, ValueError, OSError):
                pass

            pct = (p_val / total_count * 100) if has_total_target else 0.0
            alive = sum(1 for p in processes if p.is_alive())
            backlog = max(0, int(p_val) - int(s_val) - int(e_val))
            pps_avg = (float(s_val) / float(elapsed)) if elapsed > 0 else 0.0

            dt_inst = max(1e-9, now - last_inst_time)
            pps_inst = max(0.0, float(s_val - last_sent_for_inst) / dt_inst)
            last_inst_time = now
            last_sent_for_inst = s_val

            # Aggregate worker resource stats.
            rss_bytes = 0
            vram_used_bytes = 0
            pinned_bytes = 0
            pacing_actual_rps = 0.0
            pacing_rate_accuracy_sum = 0.0
            pacing_rate_accuracy_n = 0
            pacing_jitter_p99_sum = 0.0
            pacing_jitter_p99_n = 0
            pacing_ipg_mean_sum = 0.0
            pacing_ipg_mean_n = 0
            pacing_sleep_calls = 0
            pacing_busywait_cycles = 0
            pacing_so_txtime_active = 0
            pacing_txtime_errors = 0
            ai_cpu_usage_pct_sum = 0.0
            ai_cpu_usage_pct_n = 0
            ai_p95_latency_ms_max = 0.0
            ai_p99_latency_ms_max = 0.0
            ai_active_connections = 0.0
            ai_timeout_total = 0.0
            if resource_stats is not None:
                try:
                    for _, item in dict(resource_stats).items():
                        if not isinstance(item, dict):
                            continue
                        rss_bytes += int(item.get("rss_bytes", 0) or 0)
                        vram_used_bytes += int(item.get("vram_used_bytes", 0) or 0)
                        pinned_bytes += int(item.get("pinned_bytes", 0) or 0)
                        pacing_actual_rps += float(item.get("pacing_actual_rps", 0.0) or 0.0)
                        _acc = float(item.get("pacing_rate_accuracy_pct", 0.0) or 0.0)
                        if _acc > 0.0:
                            pacing_rate_accuracy_sum += _acc
                            pacing_rate_accuracy_n += 1
                        _j99 = float(item.get("pacing_jitter_p99_ns", 0.0) or 0.0)
                        if _j99 > 0.0:
                            pacing_jitter_p99_sum += _j99
                            pacing_jitter_p99_n += 1
                        _ipg = float(item.get("pacing_ipg_mean_ns", 0.0) or 0.0)
                        if _ipg > 0.0:
                            pacing_ipg_mean_sum += _ipg
                            pacing_ipg_mean_n += 1
                        pacing_sleep_calls += int(item.get("pacing_sleep_calls", 0) or 0)
                        pacing_busywait_cycles += int(item.get("pacing_busywait_cycles", 0) or 0)
                        pacing_so_txtime_active = max(
                            pacing_so_txtime_active,
                            int(item.get("pacing_so_txtime_active", 0) or 0),
                        )
                        pacing_txtime_errors += int(item.get("pacing_txtime_errors", 0) or 0)
                        _cpu_pct = float(item.get("cpu_usage_pct", 0.0) or 0.0)
                        if _cpu_pct >= 0.0:
                            ai_cpu_usage_pct_sum += _cpu_pct
                            ai_cpu_usage_pct_n += 1
                        _p95 = float(item.get("scenario_flow_latency_p95_ms", 0.0) or 0.0)
                        _p99_scenario = float(item.get("scenario_flow_latency_p99_ms", 0.0) or 0.0)
                        _p99_l7 = float(item.get("l7_handshake_p99_ms", 0.0) or 0.0)
                        ai_p95_latency_ms_max = max(ai_p95_latency_ms_max, _p95)
                        ai_p99_latency_ms_max = max(ai_p99_latency_ms_max, _p99_scenario, _p99_l7)
                        ai_active_connections += float(item.get("l7_active_sessions_peak", 0) or 0)
                        ai_timeout_total += float(item.get("quic_connect_timeout_count", 0) or 0)
                        ai_timeout_total += float(item.get("quic_handshake_timeout_count", 0) or 0)
                        ai_timeout_total += float(item.get("state_timeout_evictions", 0) or 0)
                except (AttributeError, TypeError, ValueError, OSError):
                    pass

            pacing_rate_accuracy_pct = (
                pacing_rate_accuracy_sum / pacing_rate_accuracy_n
            ) if pacing_rate_accuracy_n > 0 else 0.0
            pacing_jitter_p99_ns = (
                pacing_jitter_p99_sum / pacing_jitter_p99_n
            ) if pacing_jitter_p99_n > 0 else 0.0
            pacing_ipg_mean_ns = (
                pacing_ipg_mean_sum / pacing_ipg_mean_n
            ) if pacing_ipg_mean_n > 0 else 0.0

            error_rate_pct = (float(e_val) * 100.0 / float(p_val)) if p_val > 0 else 0.0

            # Export to Prometheus
            try:
                exporter.export({
                    "sent_total": s_val,
                    "errors_total": e_val,
                    "attempted_total": p_val,
                    "workers_active": alive,
                    "progress_pct": pct,
                    "pps_avg": pps_avg,
                    "pps_inst": pps_inst,
                    "error_rate_pct": error_rate_pct,
                    "queue_backlog": backlog,
                    "rss_bytes": rss_bytes,
                    "vram_used_bytes": vram_used_bytes,
                    "pinned_bytes": pinned_bytes,
                    "pacing_actual_rps": pacing_actual_rps,
                    "pacing_rate_accuracy_pct": pacing_rate_accuracy_pct,
                    "pacing_jitter_p99_ns": pacing_jitter_p99_ns,
                    "pacing_ipg_mean_ns": pacing_ipg_mean_ns,
                    "pacing_sleep_calls": pacing_sleep_calls,
                    "pacing_busywait_cycles": pacing_busywait_cycles,
                    "pacing_so_txtime_active": pacing_so_txtime_active,
                    "pacing_txtime_errors": pacing_txtime_errors,
                })
            except (AttributeError, TypeError, ValueError, OSError):
                pass

            # Periodic soak snapshot + threshold checks.
            if (now - ai_last_sample_ts) >= 1.0:
                ai_last_sample_ts = now
                cpu_usage = (
                    ai_cpu_usage_pct_sum / ai_cpu_usage_pct_n
                ) if ai_cpu_usage_pct_n > 0 else 0.0
                timeout_delta = max(0.0, ai_timeout_total - ai_prev_timeout_total)
                ai_prev_timeout_total = ai_timeout_total
                # p95/p99 ve timeout metriği runtime hot-path'e göre her zaman
                # bulunmayabilir; yoksa 0.0 ile doldurulur.
                ai_samples.append(
                    {
                        "ts": float(now),
                        "rps": float(pps_inst),
                        "p95_latency": float(ai_p95_latency_ms_max),
                        "p99_latency": float(ai_p99_latency_ms_max),
                        "error_rate": float(error_rate_pct / 100.0),
                        "cpu_usage": float(cpu_usage),
                        "memory_usage": float(_bytes_to_mb(rss_bytes)),
                        "active_connections": float(ai_active_connections),
                        "timeout_count": float(timeout_delta),
                    }
                )

            if soak_enabled and now >= soak_next_snapshot:
                snap = {
                    "ts": float(now),
                    "elapsed_s": float(elapsed),
                    "attempted_total": int(p_val),
                    "sent_total": int(s_val),
                    "errors_total": int(e_val),
                    "pps_avg": float(pps_avg),
                    "pps_inst": float(pps_inst),
                    "error_rate_pct": float(error_rate_pct),
                    "queue_backlog": int(backlog),
                    "rss_bytes": int(rss_bytes),
                    "vram_used_bytes": int(vram_used_bytes),
                    "pinned_bytes": int(pinned_bytes),
                    "warmup": int(elapsed < soak_warmup_s),
                }
                soak_snapshots.append(snap)
                soak_next_snapshot = now + soak_interval

                # Collect warm-up samples then lock a stable baseline from
                # the tail of warm-up window + first post-warm-up sample.
                if elapsed < soak_warmup_s:
                    soak_warmup_samples.append(snap)
                    if len(soak_warmup_samples) > 8:
                        soak_warmup_samples = soak_warmup_samples[-8:]
                elif soak_baseline is None:
                    baseline_window = list(soak_warmup_samples[-3:]) + [snap]
                    if not baseline_window:
                        baseline_window = [snap]
                    n = float(len(baseline_window))
                    soak_baseline = {
                        "rss_bytes": int(sum(int(x.get("rss_bytes", 0) or 0) for x in baseline_window) / n),
                        "vram_used_bytes": int(sum(int(x.get("vram_used_bytes", 0) or 0) for x in baseline_window) / n),
                        "pinned_bytes": int(sum(int(x.get("pinned_bytes", 0) or 0) for x in baseline_window) / n),
                    }
                    pps_vals = [float(x.get("pps_avg", 0.0) or 0.0) for x in baseline_window if float(x.get("pps_avg", 0.0) or 0.0) > 0]
                    soak_baseline_pps = float(sum(pps_vals) / len(pps_vals)) if pps_vals else 0.0
                    soak_baseline_source_count = int(len(baseline_window))
                    log_info(
                        f"[SOAK] Warm-up tamamlandı ({int(soak_warmup_s)}s). "
                        f"Baseline locked: pps={soak_baseline_pps:,.0f}, "
                        f"rss={_bytes_to_mb(int(soak_baseline.get('rss_bytes', 0))):.0f}MB"
                    )

                if error_rate_pct > thresholds["max_error_rate_pct"]:
                    _emit_alarm(
                        "error_rate_high",
                        f"Hata orani esigi asildi: {error_rate_pct:.2f}% > {thresholds['max_error_rate_pct']:.2f}%",
                        value=error_rate_pct,
                        threshold=thresholds["max_error_rate_pct"],
                    )

                if thresholds["max_backlog"] > 0 and backlog > thresholds["max_backlog"]:
                    _emit_alarm(
                        "queue_backlog_high",
                        f"Kuyruk/backlog esigi asildi: {backlog} > {thresholds['max_backlog']}",
                        value=float(backlog),
                        threshold=float(thresholds["max_backlog"]),
                    )

                if soak_baseline is not None and soak_baseline_pps > 0 and thresholds["max_pps_drop_pct"] < 100.0:
                    drop_pct = max(0.0, (soak_baseline_pps - pps_avg) * 100.0 / soak_baseline_pps)
                    if drop_pct > thresholds["max_pps_drop_pct"]:
                        _emit_alarm(
                            "pps_drift_high",
                            f"PPS drift esigi asildi: {drop_pct:.2f}% > {thresholds['max_pps_drop_pct']:.2f}%",
                            value=drop_pct,
                            threshold=thresholds["max_pps_drop_pct"],
                        )

                if soak_baseline is not None:
                    rss_growth_mb = _bytes_to_mb(max(0, int(rss_bytes) - int(soak_baseline.get("rss_bytes", 0))))
                    vram_growth_mb = _bytes_to_mb(max(0, int(vram_used_bytes) - int(soak_baseline.get("vram_used_bytes", 0))))
                    pinned_growth_mb = _bytes_to_mb(max(0, int(pinned_bytes) - int(soak_baseline.get("pinned_bytes", 0))))

                    if thresholds["max_rss_growth_mb"] > 0 and rss_growth_mb > thresholds["max_rss_growth_mb"]:
                        _emit_alarm(
                            "rss_growth_high",
                            f"RSS artis limiti asildi: {rss_growth_mb:.1f}MB > {thresholds['max_rss_growth_mb']:.1f}MB",
                            value=rss_growth_mb,
                            threshold=thresholds["max_rss_growth_mb"],
                        )
                    if thresholds["max_vram_growth_mb"] > 0 and vram_growth_mb > thresholds["max_vram_growth_mb"]:
                        _emit_alarm(
                            "vram_growth_high",
                            f"VRAM artis limiti asildi: {vram_growth_mb:.1f}MB > {thresholds['max_vram_growth_mb']:.1f}MB",
                            value=vram_growth_mb,
                            threshold=thresholds["max_vram_growth_mb"],
                        )
                    if thresholds["max_pinned_growth_mb"] > 0 and pinned_growth_mb > thresholds["max_pinned_growth_mb"]:
                        _emit_alarm(
                            "pinned_growth_high",
                            f"Pinned-memory artis limiti asildi: {pinned_growth_mb:.1f}MB > {thresholds['max_pinned_growth_mb']:.1f}MB",
                            value=pinned_growth_mb,
                            threshold=thresholds["max_pinned_growth_mb"],
                        )

            # Print only when progress changed significantly or at least every 2.0s
            if p_val != last_total or (now - last_print_time) >= max(2.0, refresh * 4):
                last_print_time = now
                last_total = p_val

                pps_str = f" ┆ PPS: {pps_avg:,.0f}" if pps_avg > 0 else ""
                soak_str = ""
                if soak_enabled:
                    soak_str = (
                        f" ┆ Backlog: {backlog:,}"
                        f" ┆ RSS: {_bytes_to_mb(rss_bytes):.0f}MB"
                        f" ┆ VRAM: {_bytes_to_mb(vram_used_bytes):.0f}MB"
                        f" ┆ PINNED: {_bytes_to_mb(pinned_bytes):.0f}MB"
                    )
                if has_total_target:
                    progress_text = f"İlerleme: {p_val:,} / {total_count:,} ({pct:.1f}%)"
                else:
                    progress_text = f"İlerleme: {p_val:,} (sürekli)"
                log_info(
                    f"{progress_text} ┆ Geçen Süre: {elapsed:.0f}s "
                    f"┆ Aktif İşçi: {alive}/{len(processes)}{pps_str}{soak_str}"
                )

            if abort_triggered:
                log_critical("[SOAK] Alarm nedeniyle güvenli otomatik sonlandirma tetiklendi.")
                for p in list(processes or []):
                    try:
                        if p.is_alive():
                            p.terminate()
                    except (AttributeError, OSError):
                        pass
                break

            time.sleep(refresh)
    except KeyboardInterrupt:
        raise

    total_elapsed = max(0.0, time.time() - start)
    if soak_enabled and thresholds["required_duration_s"] > 0 and total_elapsed < float(thresholds["required_duration_s"]):
        _emit_alarm(
            "duration_short",
            f"Soak sure esigi saglanmadi: {total_elapsed:.0f}s < {thresholds['required_duration_s']}s",
            value=float(total_elapsed),
            threshold=float(thresholds["required_duration_s"]),
        )

    passed = (len(soak_alarms) == 0) if soak_enabled else True
    return {
        "soak_enabled": bool(soak_enabled),
        "profile": str((soak_config or {}).get("profile", "none")),
        "thresholds": thresholds,
        "baseline": {
            "sample_count": int(soak_baseline_source_count),
            "pps_avg": float(soak_baseline_pps),
            "rss_bytes": int((soak_baseline or {}).get("rss_bytes", 0) if soak_baseline else 0),
            "vram_used_bytes": int((soak_baseline or {}).get("vram_used_bytes", 0) if soak_baseline else 0),
            "pinned_bytes": int((soak_baseline or {}).get("pinned_bytes", 0) if soak_baseline else 0),
        },
        "snapshot_count": int(len(soak_snapshots)),
        "snapshots": soak_snapshots,
        "ai_samples": ai_samples,
        "alarms": soak_alarms,
        "passed": bool(passed),
    }

def ethical_warning():
    """
    Etik kullanım uyarısı.
    """
    warning = "\n".join([
        _color("YASAL UYARI", ACCENT),
        _color("Bu araç, yalnızca izin verilen sistemlerde kullanılmalıdır!", ACCENT),
        _color("Yasal sorumluluk tamamen kullanıcıya aittir.", WHITE),
    ])
    print(_center(warning))
    print()

    prompt_text = "Kabul ediyor musunuz? Devam için 'YES' yazın: "
    prompt = f"{_color('❯', ACCENT)} {_color(prompt_text, WHITE)}"
    choice = input(prompt)

    if choice.strip().upper() != "YES":
        print(_color("✕ Saldırı iptal edildi!", ACCENT))
        sys.exit(0)


def validate_target_safety(
    target_ip: str,
    allow_targets: list[str] | None = None,
    allow_public: bool = False,
    deny_targets: list[str] | None = None,
) -> tuple[bool, str]:
    """
    Basic safety gate:
    - By default, only allow private/loopback IPv4 targets.
    - If allow_targets is provided, target must match one of the allowlisted
      IPv4 addresses or CIDR networks.
    - Public targets require allow_public=True.
    """
    allow_targets = allow_targets or []

    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        return False, f"Geçersiz hedef IP: {target_ip!r}"

    # Only IPv4 is supported across the codebase.
    if ip.version != 4:
        return False, "Şu an yalnızca IPv4 hedefleri destekleniyor."

    if ip.is_multicast or ip.is_unspecified:
        return False, "Geçersiz/tehlikeli hedef IP (multicast/unspecified)."

    if allow_targets:
        parsed: list[object] = []
        for item in allow_targets:
            try:
                if "/" in item:
                    parsed.append(ipaddress.ip_network(item, strict=False))
                else:
                    parsed.append(ipaddress.ip_address(item))
            except ValueError:
                return False, f"Geçersiz allowlist girdisi: {item!r}"

        for entry in parsed:
            if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv4Interface)):
                if ip in entry:
                    return True, "ok"
            elif isinstance(entry, ipaddress.IPv4Address):
                if ip == entry:
                    return True, "ok"
            elif isinstance(entry, ipaddress.IPv4Network):
                if ip in entry:
                    return True, "ok"

        return False, "Hedef IP allowlist içinde değil. (--allow-target ile izin ver)"

    # Hard deny policy: blocked targets always win.
    for item in list(deny_targets or []):
        raw = str(item or "").strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
                if ip in net:
                    return False, f"Hedef IP global denylist içinde: {raw}"
            else:
                deny_ip = ipaddress.ip_address(raw)
                if ip == deny_ip:
                    return False, f"Hedef IP global denylist içinde: {raw}"
        except ValueError:
            return False, f"Geçersiz denylist girdisi: {raw!r}"

    # Default policy: only private/loopback unless explicitly allowed.
    if ip.is_private or ip.is_loopback:
        return True, "ok"

    if allow_public:
        return True, "ok"

    return False, "Public hedefler varsayılan olarak engellenir. (--allow-public-target ile override)"
def get_gateway_mac(target_ip=None):
    """
    Resolve gateway/target MAC using route + ARP cache.
    """
    try:
        import subprocess

        # 1. Determine gateway IP from route table
        if not target_ip:
            route = subprocess.check_output(
                ["ip", "route", "show", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            ).strip()
            gateway_ip = ""
            for line in route.splitlines():
                parts = line.split()
                for idx, tok in enumerate(parts):
                    if tok == "via" and idx + 1 < len(parts):
                        gateway_ip = parts[idx + 1]
                        break
                if gateway_ip:
                    break
        else:
            try:
                route = subprocess.check_output(
                    ["ip", "route", "get", str(target_ip)],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=2,
                ).strip()
                parts = route.split()
                gateway_ip = str(target_ip)
                for idx, tok in enumerate(parts):
                    if tok == "via" and idx + 1 < len(parts):
                        gateway_ip = parts[idx + 1]
                        break
            except (subprocess.SubprocessError, OSError, ValueError):
                gateway_ip = str(target_ip)

        if not gateway_ip:
            log_warning("Gateway IP bulunamadı, broadcast MAC kullanılacak.")
            return "ff:ff:ff:ff:ff:ff"

        # 2. Read ARP cache entry
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == gateway_ip:
                    mac = parts[3].strip().lower()
                    if mac and mac != "00:00:00:00:00:00":
                        log_info(f"Gateway MAC bulundu: {mac}")
                        return mac

        log_warning("ARP yanıtı alınamadı, broadcast MAC kullanılacak.")
        return "ff:ff:ff:ff:ff:ff"
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        log_error(f"MAC çözme hatası: {e}")
        return "ff:ff:ff:ff:ff:ff"

def get_local_ip() -> str:
    """Best-effort local IPv4 address for outbound traffic.

    Uses a UDP "connect" (no packets are sent) to let the OS choose a source
    address, then reads it back via getsockname().
    """
    try:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # No traffic is emitted for UDP connect; it only selects a route.
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip:
                return ip
        finally:
            s.close()
    except OSError:
        pass

    try:
        import socket

        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"

def mac_to_int(mac_str):
    """Converts MAC address string to 48-bit integer."""
    return int(mac_str.replace(':', ''), 16)
