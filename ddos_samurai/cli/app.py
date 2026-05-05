"""Thin CLI orchestration entrypoint."""

from __future__ import annotations

from .. import utils
from ..workload_profiles import print_profiles
from .args import build_parser
from .config import build_soak_config, load_config_defaults
from .constants import CONNECTION_POOL
from .env import sync_runtime_env
from .helpers import _maybe_enable_uvloop
from .offline_modes import dispatch_offline_mode
from .profile_resolver import apply_profile, _resolve_profile_args
from .runtime import run_live_mode
from .validation import (
    _validate_distributed_args,
    _preflight_l7_capabilities,
    _preflight_lab_profile,
    _preflight_persistent_tx_backend,
    _validate_hybrid_cuda_args,
    _validate_pacing_args,
    _validate_sender_route_args,
)


def _show_account_info(license_key_arg: str) -> None:
    """Lisans hesabı özetini göster — abonelik, cihazlar, süreler."""
    import os
    from ..licensing import validate_license
    from ..licensing.hwid import get_hardware_id

    key = license_key_arg or os.getenv("SAMURAI_LICENSE_KEY", "").strip()
    if not key:
        key_file = os.path.expanduser("~/.samurai/license.key")
        if os.path.isfile(key_file):
            key = open(key_file).read().strip()
    if not key:
        utils.log_critical("Hesap bilgisi için lisans anahtarı gerekli: --license-key")
        return

    utils.log_info("┌─── Samurai Hesap Bilgisi ───────────────────────────")

    result = validate_license(key=key)
    if not result.valid:
        utils.log_critical(f"│  Lisans geçersiz: {result.reason}")
        utils.log_info("└────────────────────────────────────────────────────")
        return

    utils.log_info(f"│  Durum         : {'✓ AKTİF' if result.valid else '✗ İNAKTİF'}")
    utils.log_info(f"│  Tier          : {result.tier.value.upper()}")
    utils.log_info(f"│  E-posta       : {result.customer_email}")
    utils.log_info(f"│  Bitiş Tarihi  : {result.expires}")
    utils.log_info(f"│  Offline Cache : {'Evet' if result.offline else 'Hayır'}")
    utils.log_info("│")

    if result.limits:
        utils.log_info("│  ── Limitler ──")
        w = result.limits.max_workers if result.limits.max_workers > 0 else "Sınırsız"
        p = result.limits.max_pps if result.limits.max_pps > 0 else "Sınırsız"
        d = result.limits.max_duration_s if result.limits.max_duration_s > 0 else "Sınırsız"
        utils.log_info(f"│  Max Workers   : {w}")
        utils.log_info(f"│  Max PPS       : {p}")
        utils.log_info(f"│  Max Süre      : {d}")
        utils.log_info(f"│  Max Cihaz     : {result.limits.max_devices}")
        utils.log_info("│")

    utils.log_info("│  ── Bu Cihaz ──")
    utils.log_info(f"│  Hardware ID   : {get_hardware_id()}")
    utils.log_info(f"│  Session ID    : {result.session_id}")
    utils.log_info("│")

    if result.features:
        utils.log_info(f"│  ── Özellikler ({len(result.features)}) ──")
        line = "│  "
        for i, f in enumerate(sorted(result.features)):
            if len(line) + len(f) > 58:
                utils.log_info(line)
                line = "│  "
            line += f + ("  " if i < len(result.features) - 1 else "")
        if line.strip("│ "):
            utils.log_info(line)

    utils.log_info("│")
    utils.log_info("│  Portal: https://ddosamurai.com/hesap")
    utils.log_info("└────────────────────────────────────────────────────")


def _start_trial() -> None:
    """14 günlük Pro deneme sürümü başlat."""
    import json
    import os
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    from ..licensing.constants import LICENSE_SERVER_URL

    utils.log_info("14 günlük Pro deneme sürümü başlatılıyor...")
    utils.log_info("")

    email = input("  E-posta adresinizi girin: ").strip()
    if not email or "@" not in email:
        utils.log_critical("Geçerli bir e-posta adresi gerekli.")
        return

    try:
        url = f"{LICENSE_SERVER_URL}/api/v1/auth/trial"
        req = Request(
            url,
            data=json.dumps({"email": email}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("license_key"):
            utils.log_info("┌─── Deneme Sürümü Aktif ─────────────────────────")
            utils.log_info(f"│  Lisans Anahtarı: {data['license_key']}")
            utils.log_info(f"│  Tier           : PRO (14 gün)")
            utils.log_info(f"│  Bitiş          : {data.get('expires', '—')}")
            utils.log_info("│")
            utils.log_info(f"│  Kullanım:")
            utils.log_info(f"│  samurai --license-key {data['license_key']} -t HEDEF -p PORT")
            utils.log_info("└──────────────────────────────────────────────────")

            key_dir = os.path.expanduser("~/.samurai")
            os.makedirs(key_dir, exist_ok=True)
            key_path = os.path.join(key_dir, "license.key")
            with open(key_path, "w") as f:
                f.write(data["license_key"])
            utils.log_info(f"  ✓ Anahtar otomatik kaydedildi: {key_path}")
        else:
            utils.log_critical(f"Trial başlatılamadı: {data.get('detail', 'Bilinmeyen hata')}")

    except URLError as e:
        utils.log_critical(f"Sunucuya bağlanılamadı: {e.reason}")
        utils.log_info("  Sunucu: " + LICENSE_SERVER_URL)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as e:
        utils.log_critical(f"Trial başlatma hatası: {e}")


def main(argv=None):
    utils.print_banner()
    _maybe_enable_uvloop()
    parser = build_parser()

    temp_args, _ = parser.parse_known_args(argv)
    parser.set_defaults(**load_config_defaults(getattr(temp_args, "config", None)))
    args = parser.parse_args(argv)

    # ── License Gate ────────────────────────────────────────────────────
    from ..licensing import validate_license, deactivate_device, LicenseResult
    from ..licensing.features import has_feature, Tier
    from ..licensing.hwid import get_hardware_id

    license_key_arg = getattr(args, "license_key", "") or ""
    license_file_arg = getattr(args, "license_file", "") or ""

    # Deaktivasyon komutu
    if getattr(args, "license_deactivate", False):
        key = license_key_arg or None
        if not key:
            import os
            key = os.getenv("SAMURAI_LICENSE_KEY", "").strip() or None
        if not key:
            utils.log_critical("Deaktivasyon için lisans anahtarı gerekli: --license-key")
            raise SystemExit(1)
        ok, msg = deactivate_device(key)
        if ok:
            utils.log_info(f"✓ {msg}")
            raise SystemExit(0)
        else:
            utils.log_critical(f"✗ {msg}")
            raise SystemExit(1)

    # Aktivasyon komutu (açık cihaz kaydı)
    if getattr(args, "license_activate", False):
        key = license_key_arg or None
        if not key:
            import os
            key = os.getenv("SAMURAI_LICENSE_KEY", "").strip() or None
        if not key:
            utils.log_critical("Aktivasyon için lisans anahtarı gerekli: --license-key")
            raise SystemExit(1)
        result = validate_license(key=key)
        if result.valid:
            utils.log_info("✓ Cihaz başarıyla etkinleştirildi!")
            utils.log_info(f"  Tier       : {result.tier.value.upper()}")
            utils.log_info(f"  Bitiş      : {result.expires}")
            utils.log_info(f"  Hardware ID: {get_hardware_id()}")
            utils.log_info(f"  Session    : {result.session_id}")
            raise SystemExit(0)
        else:
            utils.log_critical(f"Aktivasyon başarısız: {result.reason}")
            raise SystemExit(1)

    # Hesap bilgisi komutu
    if getattr(args, "license_account", False):
        _show_account_info(license_key_arg)
        raise SystemExit(0)

    # Trial başlatma komutu
    if getattr(args, "license_trial", False):
        _start_trial()
        raise SystemExit(0)

    # Lisans doğrulama
    license_result = validate_license(
        key=license_key_arg or None,
        key_file=license_file_arg or None,
    )

    # Lisans bilgisi komutu
    if getattr(args, "license_info", False):
        if license_result.valid:
            utils.log_info(f"Lisans Durumu  : AKTİF")
            utils.log_info(f"Tier           : {license_result.tier.value.upper()}")
            utils.log_info(f"Bitiş Tarihi   : {license_result.expires}")
            utils.log_info(f"E-posta        : {license_result.customer_email}")
            utils.log_info(f"Özellikler     : {', '.join(license_result.features)}")
            if license_result.limits:
                utils.log_info(f"Max Workers    : {license_result.limits.max_workers or 'Sınırsız'}")
                utils.log_info(f"Max PPS        : {license_result.limits.max_pps or 'Sınırsız'}")
                utils.log_info(f"Max Cihaz      : {license_result.limits.max_devices}")
            utils.log_info(f"Offline Cache  : {'Evet' if license_result.offline else 'Hayır'}")
            utils.log_info(f"Hardware ID    : {get_hardware_id()}")
        else:
            utils.log_critical(f"Lisans geçersiz: {license_result.reason}")
        raise SystemExit(0 if license_result.valid else 1)

    # Lisans kontrolü
    if not license_result.valid:
        utils.log_critical(f"Lisans doğrulaması başarısız:\n{license_result.reason}")
        raise SystemExit(78)  # EX_CONFIG

    # Lisans bilgisi logla
    tier_display = license_result.tier.value.upper()
    offline_tag = " (offline cache)" if license_result.offline else ""
    utils.log_info(
        f"Lisans aktif: {tier_display} | "
        f"Bitiş: {license_result.expires}{offline_tag}"
    )

    # Lisans sonucunu args namespace'ine ekle (downstream feature gating için)
    args._license_result = license_result
    # ── License Gate End ────────────────────────────────────────────────

    # ── Auto-Update Check ──────────────────────────────────────────────
    try:
        from ..licensing.updater import check_for_updates
        check_for_updates()
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass  # Güncelleme kontrolü asla çalışmayı engellememeli
    # ── Auto-Update Check End ──────────────────────────────────────────

    _resolve_profile_args(parser, args, argv)

    if getattr(args, "list_profiles", False):
        print_profiles()
        raise SystemExit(0)

    apply_profile(args, argv)
    _resolve_profile_args(parser, args, argv)
    _validate_pacing_args(parser, args)
    _validate_hybrid_cuda_args(parser, args)
    _validate_sender_route_args(parser, args)
    _validate_distributed_args(parser, args)
    _preflight_lab_profile(parser, args)
    _preflight_persistent_tx_backend(parser, args)
    _preflight_l7_capabilities(parser, args)

    traffic_model_mode = str(getattr(args, "traffic_model", "none") or "none").strip().lower()
    if traffic_model_mode == "mamba2":
        parser.error(
            "--traffic-model mamba2 runtime entegrasyonu geçici olarak devre dışı. "
            "Ayrı eğitim/çıkarım akışı için training/mamba2_monolith.py train|eval|infer-plan kullanın."
        )

    global CONNECTION_POOL
    try:
        CONNECTION_POOL = max(1, int(args.connection_pool))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass

    # ── License-based Worker Limit ──────────────────────────────────────
    if license_result.limits and license_result.limits.max_workers > 0:
        if args.workers > license_result.limits.max_workers:
            utils.log_warning(
                f"Worker sayısı lisans limitine ({license_result.limits.max_workers}) "
                f"düşürüldü. (İstenen: {args.workers})"
            )
            args.workers = license_result.limits.max_workers
    # ── License-based Worker Limit End ──────────────────────────────────

    want_report = bool(getattr(args, "run_report", False)) or bool(getattr(args, "gpu_pcap_run_report", False))
    report_fmt = str(getattr(args, "run_report_format", getattr(args, "gpu_pcap_run_report_format", "both")))
    report_dir = str(getattr(args, "run_report_dir", "reports/runs"))
    report_base = str(getattr(args, "run_report_out", "")).strip() or str(getattr(args, "gpu_pcap_run_report_out", "")).strip()
    if bool(getattr(args, "kpi_hard_fail", False)) or str(getattr(args, "kpi_gate_profile", "off") or "off") != "off":
        want_report = True

    soak_cfg = build_soak_config(args)
    env_ctx = sync_runtime_env(args)
    runtime_ctx = {
        "mode": str(getattr(args, "traffic_model", "none") or "none"),
        "model_name": "none",
        "checkpoint_id": "",
        "seed": int(getattr(args, "traffic_model_seed", 1337) or 1337),
        "plan_id": "",
        "session_count": 0,
        "event_count": 0,
        "fallback_used": False,
        "fallback_reason": "none",
        "validation_errors": [],
    }
    report_ctx = {
        "want_report": want_report,
        "report_fmt": report_fmt,
        "report_dir": report_dir,
        "report_base": report_base,
        "loss_report_out": env_ctx["loss_report_out"],
    }

    offline_result = dispatch_offline_mode(args, parser, report_ctx, runtime_ctx)
    if offline_result is not None:
        raise SystemExit(offline_result)
    role = str(getattr(args, "role", "standalone") or "standalone").strip().lower()
    if role == "master":
        from .distributed import run_distributed_master

        raise SystemExit(run_distributed_master(args, parser, report_ctx, runtime_ctx))
    if role == "slave":
        from .distributed import run_distributed_slave

        raise SystemExit(run_distributed_slave(args, parser))
    raise SystemExit(run_live_mode(args, parser, argv, soak_cfg, report_ctx, runtime_ctx))
