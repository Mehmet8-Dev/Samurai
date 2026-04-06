"""CLI config loading and derived config helpers."""

from __future__ import annotations

import os

import yaml

from .. import utils
from .constants import _SOAK_PROFILE_PRESETS


def load_config_defaults(config_path: str | None) -> dict:
    defaults_from_config = {}
    if not config_path:
        return defaults_from_config
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f) or {}
        for main_key, value in config_data.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    dest = f"{main_key}_{sub_key}".replace("-", "_")
                    defaults_from_config[dest] = sub_value
            else:
                defaults_from_config[main_key] = value
    except FileNotFoundError:
        utils.log_critical(f"Konfigürasyon dosyası bulunamadı: {config_path}")
        raise SystemExit(1)
    except Exception as e:
        utils.log_critical(f"Konfigürasyon dosyası okunurken hata: {e}")
        raise SystemExit(1)
    return defaults_from_config


def build_soak_config(args) -> dict | None:
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
