"""Offline license cache — şifreli yerel doğrulama önbelleği.

Lisans başarıyla doğrulandığında sonuç şifrelenerek diske yazılır.
Sunucuya ulaşılamadığında, grace period süresi içinde bu cache'ten
çalışmaya devam edilir (varsayılan: 72 saat).

Şifreleme: Fernet (AES-128-CBC) — anahtar HWID'den türetilir,
böylece cache yalnızca aynı makinede açılabilir.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Optional

from .constants import CACHE_DIR, CACHE_FILE, OFFLINE_GRACE_PERIOD_S
from .features import LicenseResult, Tier, TierLimits

# Fernet opsiyonel — yoksa cache devre dışı kalır.
try:
    from cryptography.fernet import Fernet, InvalidToken

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _derive_key(hwid: str) -> bytes:
    """HWID'den Fernet-uyumlu 32-byte base64 anahtar türet."""
    raw = hashlib.sha256(f"samurai-cache-{hwid}".encode()).digest()
    return base64.urlsafe_b64encode(raw)


def save_cache(result: LicenseResult, hwid: str) -> bool:
    """Doğrulama sonucunu şifreli olarak diske yaz.

    Returns:
        True — başarılı, False — yazılamadı.
    """
    if not _HAS_CRYPTO:
        return False

    try:
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)

        payload = {
            "valid": result.valid,
            "tier": result.tier.value if isinstance(result.tier, Tier) else str(result.tier),
            "features": list(result.features or []),
            "expires": result.expires,
            "customer_email": result.customer_email,
            "session_id": result.session_id,
            "cached_at": time.time(),
            "limits": None,
        }
        if result.limits is not None:
            payload["limits"] = {
                "max_workers": result.limits.max_workers,
                "max_pps": result.limits.max_pps,
                "max_duration_s": result.limits.max_duration_s,
                "max_devices": result.limits.max_devices,
            }

        key = _derive_key(hwid)
        f = Fernet(key)
        token = f.encrypt(json.dumps(payload).encode("utf-8"))

        with open(CACHE_FILE, "wb") as fp:
            fp.write(token)
        os.chmod(CACHE_FILE, 0o600)
        return True
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return False


def load_cache(hwid: str) -> Optional[LicenseResult]:
    """Önbellekten lisans sonucunu oku.

    Grace period kontrolü burada yapılır.  Süresi dolmuş cache
    ``None`` döndürür.

    Returns:
        LicenseResult veya None.
    """
    if not _HAS_CRYPTO:
        return None

    if not os.path.isfile(CACHE_FILE):
        return None

    try:
        key = _derive_key(hwid)
        f = Fernet(key)

        with open(CACHE_FILE, "rb") as fp:
            token = fp.read()

        plaintext = f.decrypt(token)
        payload = json.loads(plaintext.decode("utf-8"))

        cached_at = float(payload.get("cached_at", 0))
        age = time.time() - cached_at

        if age > OFFLINE_GRACE_PERIOD_S:
            # Grace period dolmuş → cache geçersiz
            _remove_cache()
            return None

        limits = None
        if payload.get("limits"):
            lm = payload["limits"]
            limits = TierLimits(
                max_workers=int(lm.get("max_workers", 0)),
                max_pps=int(lm.get("max_pps", 0)),
                max_duration_s=int(lm.get("max_duration_s", 0)),
                max_devices=int(lm.get("max_devices", 1)),
            )

        tier_str = str(payload.get("tier", "community"))
        try:
            tier = Tier(tier_str)
        except ValueError:
            tier = Tier.COMMUNITY

        return LicenseResult(
            valid=bool(payload.get("valid", False)),
            tier=tier,
            features=list(payload.get("features", [])),
            limits=limits,
            expires=str(payload.get("expires", "")),
            customer_email=str(payload.get("customer_email", "")),
            session_id=str(payload.get("session_id", "")),
            reason="offline_cache",
            offline=True,
        )

    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        _remove_cache()
        return None


def _remove_cache() -> None:
    """Cache dosyasını güvenli şekilde sil."""
    try:
        if os.path.isfile(CACHE_FILE):
            os.remove(CACHE_FILE)
    except OSError:
        pass


def clear_cache() -> None:
    """Public API: cache'i temizle."""
    _remove_cache()
