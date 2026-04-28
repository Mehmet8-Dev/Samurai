"""Auto-update check — GitHub Releases üzerinden versiyon kontrolü.

CLI başlatıldığında (arka planda, bloklamadan) en son sürümü kontrol eder
ve kullanıcıyı bilgilendirir.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .. import __version__, utils

_GITHUB_RELEASES_URL = os.getenv(
    "SAMURAI_RELEASES_URL",
    "https://api.github.com/repos/Mehmet8-Dev/Samurai/releases/latest",
)

_CHECK_INTERVAL_S = 86400  # 24 saat
_CACHE_FILE = Path.home() / ".samurai" / ".update_check"


def _should_check() -> bool:
    """Son kontrolden bu yana yeterli süre geçti mi?"""
    if os.getenv("SAMURAI_SKIP_UPDATE_CHECK", "").strip().lower() in {"1", "true"}:
        return False

    try:
        if _CACHE_FILE.exists():
            last_check = float(_CACHE_FILE.read_text().strip())
            if (time.time() - last_check) < _CHECK_INTERVAL_S:
                return False
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass

    return True


def _save_check_time() -> None:
    """Son kontrol zamanını kaydet."""
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(str(time.time()))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass


def _fetch_latest_version() -> Optional[str]:
    """GitHub Releases API'den en son versiyon tag'ini al."""
    try:
        req = Request(
            _GITHUB_RELEASES_URL,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": f"DDoSamurai/{__version__}",
            },
        )
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            tag = str(data.get("tag_name", "")).strip()
            if tag.startswith("v"):
                tag = tag[1:]
            return tag or None
    except (URLError, OSError, json.JSONDecodeError):
        return None


def _parse_semver(version: str) -> tuple[int, ...]:
    """Basit semver parse — (major, minor, patch)."""
    parts = version.strip().lstrip("v").split(".")
    result = []
    for p in parts[:3]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result)


def check_for_updates() -> None:
    """Güncelleme kontrolü yap ve kullanıcıyı bilgilendir.

    Bu fonksiyon CLI başlatılırken çağrılır, başarısız olursa sessizce geçer.
    """
    if not _should_check():
        return

    _save_check_time()

    latest = _fetch_latest_version()
    if latest is None:
        return

    current = _parse_semver(__version__)
    remote = _parse_semver(latest)

    if remote > current:
        utils.log_info(
            f"┌─ Yeni sürüm mevcut: v{latest} (mevcut: v{__version__})\n"
            f"│  İndirmek için: https://github.com/Mehmet8-Dev/Samurai/releases/latest\n"
            f"└─ Bu kontrolü kapatmak için: SAMURAI_SKIP_UPDATE_CHECK=1"
        )
