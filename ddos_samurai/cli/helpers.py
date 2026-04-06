"""Small helper utilities for the CLI package."""

from __future__ import annotations

import argparse
import ctypes
import os

from .. import utils


def _maybe_enable_uvloop() -> bool:
    # Avoid side effects (prints / event loop changes) at import time.
    try:
        import uvloop

        uvloop.install()
        return True
    except Exception:
        return False


def _arg_bool(value):
    """argparse bool parser that accepts common true/false spellings."""
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "f", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError("Boolean değer bekleniyor: true/false")


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


def _normalize_dataplane_core_mode(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "on": "auto",
        "enable": "auto",
        "enabled": "auto",
        "true": "auto",
        "1": "auto",
        "off": "off",
        "disable": "off",
        "disabled": "off",
        "false": "off",
        "0": "off",
        "must": "required",
        "strict": "required",
        "hard": "required",
    }
    norm = aliases.get(raw, raw)
    if norm in {"off", "auto", "required"}:
        return norm
    return "off"


def _normalize_afpacket_hugepage_mode(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    aliases = {
        "on": "auto",
        "enable": "auto",
        "enabled": "auto",
        "true": "auto",
        "1": "auto",
        "off": "off",
        "disable": "off",
        "disabled": "off",
        "false": "off",
        "0": "off",
        "must": "required",
        "strict": "required",
        "hard": "required",
    }
    norm = aliases.get(raw, raw)
    if norm in {"off", "auto", "required"}:
        return norm
    return "off"


def is_admin() -> bool:
    """Checks if the current process has administrator/root privileges."""
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def print_distributed_info(role) -> None:
    """Print information about the distributed attack mode."""
    if role == "master":
        utils.log_info("Distributed attack modu: MASTER - Slave'ler bekleniyor.")
    elif role == "slave":
        utils.log_info("Distributed attack modu: SLAVE - Master'a bağlanılıyor.")
    else:
        utils.log_info("Distributed attack modu: STANDALONE")
