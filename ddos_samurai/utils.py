import time
from datetime import datetime
import ipaddress
import logging
import sys
import random
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table

# Professional theme: Gri, Kırmızı, Beyaz
samurai_theme = Theme({
    "info": "white",
    "warning": "red",
    "error": "bold red",
    "critical": "bold red",
    "timestamp": "bright_black",
    "tag": "bold red",
    "success": "white",
    "system": "white",
    "title": "bold red",
    "subtitle": "bright_black",
    "accent": "red"
})

console = Console(theme=samurai_theme)

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_info(msg, protocol=None):
    timestamp = get_timestamp()
    proto_str = f" [{protocol.upper()}]" if protocol else ""
    console.print(f"[bright_black][{timestamp}][/bright_black] [bold red]●[/bold red] [white]{msg}{proto_str}[/white]")
    logging.info(f"[{timestamp}] [INFO]{' (' + protocol.upper() + ')' if protocol else ''} {msg}")

def log_warning(msg):
    timestamp = get_timestamp()
    console.print(f"[bright_black][{timestamp}][/bright_black] [bold red]⚠[/bold red]  [red]{msg}[/red]")
    logging.warning(f"[{timestamp}] [WARNING] {msg}")

def log_error(msg):
    timestamp = get_timestamp()
    console.print(f"[bright_black][{timestamp}][/bright_black] [bold red]✗[/bold red]  [bold red]{msg}[/bold red]")
    logging.error(f"[{timestamp}] [ERROR] {msg}")

def log_critical(msg):
    timestamp = get_timestamp()
    console.print(f"[bright_black][{timestamp}][/bright_black] [bold red]▲[/bold red]  [bold red]{msg}[/bold red]")
    logging.critical(f"[{timestamp}] [CRITICAL] {msg}")

def print_banner():
    """
    Samurai banner'ini terminal'de gosterir.
    Profesyonel, minimalist tasarım.
    """
    console.clear()
    
    banners = [
        # Banner 1: Samurai Mask
        r"""
          .                                                      .
        .n                   .                 .                  n.
      . .dP                  dP                   9b                 9b. .
     4    qXb         .       dx                     xb       .        dXp    t
    dX.    9Xb      .dXb    __                     __    dXb.     dXp     .Xb
    9XXb._       _.dXXXXb dXXXXbo.               .odXXXXb dXXXXb._       _.dXXP
     9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
      `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
        `9XXXXXXXXXXXP' `9XX'   DIE    `98v8P'  HONOR   `XXP' `9XXXXXXXXXXXP' 
            ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
                            )b.  .dbo.dP'`v'`9b.odb.  .dX(
                          ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
                         dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
                        dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
                        9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
                         `'      9XXXXXX(   )XXXXXXP      `'
                                  XXXX X.`v'.X XXXX
                                  XP^X'`b   d'`X^XX
                                  `b  `       '  d'
                                   `             '

                    ███████╗███████╗█████╗ ███╗██    ██╗██╗██╗█ ████╗██╗██╗ 
                    ██╔════╝██╔══██╗████╗ ████║██║   ██║██╔══██╗██╔══██╗██║
                    ███████╗███████║██╔████╔██║██║   ██║██████╔╝███████║██║
                    ╚════██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║██║
                    ███████║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██║
                    ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
        """, 
        # Banner 2: Börü
        r"""
          .                                                      .
        .n                   .                 .                  n.
      .  dP                  dP                   9b                 9b  .
     4    qXb         .      dXb                 dXb      .        dXp    t
    dX.    9Xb      .dXb   .dXXXb.             .dXXXb.   dXb.     dXp    .Xb
    9XXb._       _.dXXXXXXXXXXXXXXXbo.       .odXXXXXXXXXXXXXXXb._       _.dXXP
     9XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXo.   .oXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXP
      `9XXXXXXXXXXXXXXP'  `9XXXXXXXXXXXXb dXXXXXXXXXXXP'  `9XXXXXXXXXXXXXXP'
        `9XXXXXXXXXP'  BÖRÜ  `9XXXXXXXb.   .dXXXXXXXP'  ASENA  `9XXXXXXXXXP'
            ~~~~~~~           9X.   `9bo. .od9'   .XP           ~~~~~~~
                               )b.    `9bd9'    .d(
                             ,dXXXb.   dXXb   .dXXXb.
                            dXXXXXXXb.dXXXXb.dXXXXXXXb
                           dXXXP' `9XXXXXXXXXXXXXXXXXXXb
                          dXXXP     9XXb'   `dXXP `9XXXb
                          9XXP       `9Xb   dXP'   `XXP
                           `'          9XbdXP       `''
                                        9XX9
                                         `'
        """
    ]
    
    selected_banner = random.choice(banners)
    console.print(Text(selected_banner, style="bold red"))
    
    # Divider with gri tone
    divider = Text("─" * 80, style="bright_black")
    console.print(Align.center(divider))
    
    quotes = [
        "Tengri täŋri bolmış, täg täg etilse bolur",  
        "Kut sökün, kut yaratır - kumandanıŋ kut'u cahan kut'udur",
        "Süyü tut, su tutmaguči tut ettim seni", 
        "Bilge tanar, buqa aç - bilgelik bozkırda açlık çekmez", 
        "Atïm atï, atlï atï aç - atlının ünü havada yükselmek için", 
        "Turuk könül, birle körümlätti - sabit kalp, birlikte görmüş",  
        "Erig tutdı, erig ètdi koyun - güçü tuttu, gücü kullandı",
        "Takï kagan, takï taŋrï - taç şahı, taç tanrı gibi",  
        "Börï böri bilür - kurdu Kurt bilir",
        "Yer su taŋrï kut verdi, ata taŋrï kut sïzïladï", 
    ]
    
    quote = random.choice(quotes)
    quote_text = Text(f"▐  {quote}  ▌", style="white")
    console.print(Align.center(quote_text))
    
    # Divider with gri tone
    divider_end = Text("─" * 80, style="bright_black")
    console.print(Align.center(divider_end))
    console.print()

def print_system_status(args):
    """
    Sistem durumunu ve saldırı parametrelerini gösterir.
    Gri, kırmızı, beyaz tema kullanılır.
    """
    table = Table(
        show_header=True,
        header_style="bold red",
        border_style="bright_black",
        width=85
    )
    
    table.add_column("Bileşen", style="white", justify="right", width=30)
    table.add_column("Durum / Değer", style="bold white", justify="left", width=50)
    
    gpu_status = "[bold red]AKTİF (CUDA)[/bold red]" if 'cupy' in sys.modules else "[white]HAZIR (CPU)[/white]"
    
    table.add_row("[GPU]  ", gpu_status)
    table.add_row("[WORKERS]  ", f"[bold red]{args.workers}[/bold red]")
    table.add_row("[PROTOCOL]", f"[bold white]{args.protocol.upper()}[/bold white]")
    table.add_row("[TARGET]  ", f"[bold red]{args.target}:{args.port}[/bold red]")
    table.add_row("[VECTOR]  ", f"[bold white]{args.attack_vector.upper()}[/bold white]")

    stealth_status = "[bold red]AÇIK[/bold red]" if bool(getattr(args, "stealth_mode", False)) else "[bright_black]KAPALI[/bright_black]"
    table.add_row("[STEALTH] ", stealth_status)
    
    footer = Text(
        f"┆ {get_timestamp()} ┆ workers={args.workers} ┆", 
        style="bright_black"
    )
    
    status_panel = Panel(
        Align.center(table),
        title="[bold red]───── SİSTEM BİLGİLERİ ─────[/bold red]",
        subtitle=footer,
        border_style="bright_black",
        padding=(1, 1),
        expand=False
    )

    console.print(Align.center(status_panel))
    console.print()


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
    soak_snapshots = []
    soak_alarms = []
    soak_alarm_codes = set()
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

    def _bytes_to_mb(v: int) -> float:
        return float(v) / (1024.0 * 1024.0)

    def _emit_alarm(code: str, message: str, value=None, threshold=None):
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
            except Exception:
                pass

            pct = (p_val / total_count * 100) if total_count else 0
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
                except Exception:
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
            except Exception:
                pass

            # Periodic soak snapshot + threshold checks.
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
                log_info(
                    f"İlerleme: {p_val:,} / {total_count:,} ({pct:.1f}%) ┆ Geçen Süre: {elapsed:.0f}s "
                    f"┆ Aktif İşçi: {alive}/{len(processes)}{pps_str}{soak_str}"
                )

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
        "alarms": soak_alarms,
        "passed": bool(passed),
    }

def ethical_warning():
    """
    Etik kullanım uyarısı.
    """
    warning_box = Panel(
        "[bold red]Bu araç, yalnızca izin verilen sistemlerde kullanılmalıdır![/bold red]\n"
        "[white]Yasal sorumluluk tamamen kullanıcıya aittir.[/white]",
        title="[bold red]⚠️  YASAL UYARI ⚠️[/bold red]",
        border_style="red",
        padding=(1, 2),
        expand=False
    )
    console.print(Align.center(warning_box))
    console.print()
    
    choice = console.input("[bold red]❯[/bold red] [white]Kabul ediyor musunuz? Devam için 'YES' yazın: [/white]")
    
    if choice.strip().upper() != "YES":
        console.print("[bold red]✗ Saldırı iptal edildi![/bold red]")
        sys.exit(0)


def validate_target_safety(
    target_ip: str,
    allow_targets: list[str] | None = None,
    allow_public: bool = False,
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
            except Exception:
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

    # Default policy: only private/loopback unless explicitly allowed.
    if ip.is_private or ip.is_loopback:
        return True, "ok"

    if allow_public:
        return True, "ok"

    return False, "Public hedefler varsayılan olarak engellenir. (--allow-public-target ile override)"
def get_gateway_mac(target_ip=None):
    """
    P2 FIX #19: Resolves the gateway MAC address for the target.
    Uses scapy for ARP resolution.
    """
    try:
        # Import scapy components inside the try to allow graceful fallback if unavailable
        from scapy.all import ARP, Ether, srp
        import subprocess

        # 1. Get default gateway IP if not provided
        if not target_ip:
            # Simple way to get gateway IP (may need refinement on non-linux systems)
            cmd = "ip route show default | awk '/default/ {print $3}'"
            gateway_ip = subprocess.check_output(cmd, shell=True).decode().strip()
        else:
            gateway_ip = target_ip  # If we want to resolve a specific IP's MAC

        if not gateway_ip:
            log_warning("Gateway IP bulunamadı, broadcast MAC kullanılacak.")
            return "ff:ff:ff:ff:ff:ff"

        # 2. ARP Request
        log_info(f"Gateway MAC çözülüyor: {gateway_ip}...")
        ans, _unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip), timeout=2, verbose=False)

        for _snd, rcv in ans:
            # rcv may expose .src or require sprintf depending on scapy version
            mac = getattr(rcv, "src", None) or rcv.sprintf(r"%Ether.src%")
            log_info(f"Gateway MAC bulundu: {mac}")
            return mac

        log_warning("ARP yanıtı alınamadı, broadcast MAC kullanılacak.")
        return "ff:ff:ff:ff:ff:ff"
    except Exception as e:
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
    except Exception:
        pass

    try:
        import socket

        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"

def mac_to_int(mac_str):
    """Converts MAC address string to 48-bit integer."""
    return int(mac_str.replace(':', ''), 16)
