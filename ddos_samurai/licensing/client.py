"""License HTTP client — sunucu ile iletişim katmanı.

Üç ana fonksiyon:
  - validate_license(): Başlangıçta lisans doğrulama
  - send_heartbeat(): Çalışma sırasında periyodik heartbeat
  - deactivate_device(): Cihaz deaktivasyonu
"""

from __future__ import annotations

import json
import os
import platform
import re
import uuid
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .. import __version__
from .cache import clear_cache, load_cache, save_cache
from .constants import (
    DEACTIVATE_ENDPOINT,
    DEV_MODE,
    HEARTBEAT_ENDPOINT,
    LICENSE_KEY_FILE,
    LICENSE_KEY_PATTERN,
    LICENSE_SERVER_URL,
    REQUEST_TIMEOUT_S,
    VALIDATE_ENDPOINT,
)
from .features import (
    LicenseResult,
    Tier,
    TierLimits,
    get_tier_features,
    get_tier_limits,
)
from .hwid import get_hardware_id


# ── Key Resolution ──────────────────────────────────────────────────────────


def _resolve_key(
    key: Optional[str] = None,
    key_file: Optional[str] = None,
) -> Optional[str]:
    """Lisans anahtarını çeşitli kaynaklardan çözümle.

    Öncelik sırası:
      1. Doğrudan ``key`` parametresi (--license-key)
      2. ``key_file`` parametresindeki dosya (--license-file)
      3. SAMURAI_LICENSE_KEY ortam değişkeni
      4. ~/.samurai/license.key dosyası
    """
    # 1. Doğrudan key
    if key and key.strip():
        return key.strip()

    # 2. Belirtilen dosya
    if key_file and os.path.isfile(key_file):
        try:
            content = open(key_file, "r", encoding="utf-8").read().strip()
            if content:
                return content
        except Exception:
            pass

    # 3. Ortam değişkeni
    env_key = os.getenv("SAMURAI_LICENSE_KEY", "").strip()
    if env_key:
        return env_key

    # 4. Varsayılan dosya
    if os.path.isfile(LICENSE_KEY_FILE):
        try:
            content = open(LICENSE_KEY_FILE, "r", encoding="utf-8").read().strip()
            if content:
                return content
        except Exception:
            pass

    return None


def _validate_key_format(key: str) -> bool:
    """Lisans anahtarının format kontrolü."""
    return bool(re.match(LICENSE_KEY_PATTERN, key.strip().upper()))


# ── HTTP Helpers ────────────────────────────────────────────────────────────


def _post_json(endpoint: str, payload: dict) -> dict:
    """License server'a JSON POST isteği gönder."""
    url = f"{LICENSE_SERVER_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")

    req = Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"DDoSamurai/{__version__}",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            body = {}
        return {
            "valid": False,
            "error": True,
            "status_code": exc.code,
            "reason": body.get("detail", body.get("message", str(exc))),
        }
    except URLError:
        raise  # Network hatası → caller'da offline cache'e düş
    except Exception as exc:
        return {"valid": False, "error": True, "reason": str(exc)}


# ── Dev Mode Result ─────────────────────────────────────────────────────────


def _dev_mode_result() -> LicenseResult:
    """Geliştirme modunda tüm özellikler açık."""
    return LicenseResult(
        valid=True,
        tier=Tier.ENTERPRISE,
        features=get_tier_features(Tier.ENTERPRISE),
        limits=get_tier_limits(Tier.ENTERPRISE),
        expires="dev-mode",
        customer_email="dev@localhost",
        reason="dev_mode",
        session_id=str(uuid.uuid4()),
        offline=False,
    )


# ── Main API ────────────────────────────────────────────────────────────────


def validate_license(
    key: Optional[str] = None,
    key_file: Optional[str] = None,
) -> LicenseResult:
    """Lisans doğrulama — CLI başlatıldığında çağrılır.

    Akış:
      1. Dev mode kontrolü
      2. Key çözümleme
      3. Format doğrulama
      4. Sunucu ile doğrulama
      5. Başarısız → offline cache kontrolü
      6. Sonucu cache'le

    Args:
        key: Doğrudan lisans anahtarı.
        key_file: Lisans anahtarı dosyası.

    Returns:
        LicenseResult — valid=True ise çalışma devam eder.
    """

    # ── Dev mode ────────────────────────────────────────────────────────
    if DEV_MODE:
        return _dev_mode_result()

    # ── Key resolution ──────────────────────────────────────────────────
    resolved_key = _resolve_key(key=key, key_file=key_file)

    if not resolved_key:
        return LicenseResult(
            valid=False,
            reason=(
                "Lisans anahtarı bulunamadı. Belirtme yöntemleri:\n"
                "  1. --license-key SAM-XXXX-XXXX-XXXX-XXXX\n"
                "  2. --license-file /path/to/license.key\n"
                "  3. SAMURAI_LICENSE_KEY ortam değişkeni\n"
                "  4. ~/.samurai/license.key dosyası\n\n"
                "Lisans satın almak için: https://ddosamurai.com/pricing"
            ),
        )

    resolved_key = resolved_key.strip().upper()

    # ── Format kontrolü ─────────────────────────────────────────────────
    if not _validate_key_format(resolved_key):
        return LicenseResult(
            valid=False,
            reason=f"Geçersiz lisans anahtarı formatı: {resolved_key}\n"
            f"Beklenen format: SAM-XXXX-XXXX-XXXX-XXXX",
        )

    # ── HWID ────────────────────────────────────────────────────────────
    hwid = get_hardware_id()

    # ── Sunucu doğrulama ────────────────────────────────────────────────
    try:
        resp = _post_json(VALIDATE_ENDPOINT, {
            "license_key": resolved_key,
            "hardware_id": hwid,
            "app_version": __version__,
            "hostname": platform.node() or "unknown",
            "os_info": f"{platform.system()} {platform.release()}",
        })
    except (URLError, OSError):
        # Sunucuya ulaşılamadı → offline cache dene
        cached = load_cache(hwid)
        if cached is not None:
            return cached
        return LicenseResult(
            valid=False,
            reason=(
                "Lisans sunucusuna ulaşılamadı ve geçerli offline önbellek bulunamadı.\n"
                "İnternet bağlantınızı kontrol edin veya daha sonra tekrar deneyin."
            ),
        )

    # ── Yanıt işleme ───────────────────────────────────────────────────
    if resp.get("error"):
        status_code = int(resp.get("status_code", 0))
        reason = str(resp.get("reason", "Bilinmeyen hata"))

        if status_code == 401:
            reason = f"Geçersiz lisans anahtarı. {reason}"
        elif status_code == 403:
            reason = (
                f"Aboneliğiniz sona ermiş veya askıya alınmış. {reason}\n"
                "Yenilemek için: https://ddosamurai.com/portal"
            )
        elif status_code == 429:
            reason = (
                f"Cihaz aktivasyon limitine ulaşıldı. {reason}\n"
                "Bir cihazı kaldırmak için: samurai deactivate"
            )
        else:
            # Sunucu hatası → offline cache dene
            cached = load_cache(hwid)
            if cached is not None:
                return cached
            reason = f"Lisans sunucusu hatası ({status_code}): {reason}"

        return LicenseResult(valid=False, reason=reason)

    if not resp.get("valid", False):
        return LicenseResult(
            valid=False,
            reason=str(resp.get("reason", "Lisans doğrulanamadı.")),
        )

    # ── Başarılı — sonuç oluştur ────────────────────────────────────────
    tier_str = str(resp.get("tier", "community")).strip().lower()
    try:
        tier = Tier(tier_str)
    except ValueError:
        tier = Tier.COMMUNITY

    features = resp.get("features") or get_tier_features(tier)
    limits_data = resp.get("limits")
    if limits_data and isinstance(limits_data, dict):
        limits = TierLimits(
            max_workers=int(limits_data.get("max_workers", 0)),
            max_pps=int(limits_data.get("max_pps", 0)),
            max_duration_s=int(limits_data.get("max_duration_s", 0)),
            max_devices=int(limits_data.get("max_devices", 1)),
        )
    else:
        limits = get_tier_limits(tier)

    result = LicenseResult(
        valid=True,
        tier=tier,
        features=list(features),
        limits=limits,
        expires=str(resp.get("expires", "")),
        customer_email=str(resp.get("customer_email", "")),
        session_id=str(resp.get("session_id", str(uuid.uuid4()))),
        reason="server_validated",
        offline=False,
    )

    # Cache'e yaz (offline grace period için)
    save_cache(result, hwid)

    return result


def send_heartbeat(
    license_key: str,
    session_id: str,
) -> bool:
    """Çalışma sırasında periyodik heartbeat gönder.

    Returns:
        True — aktif, False — lisans iptal/askıya alınmış.
    """
    if DEV_MODE:
        return True

    hwid = get_hardware_id()

    try:
        resp = _post_json(HEARTBEAT_ENDPOINT, {
            "license_key": license_key.strip().upper(),
            "hardware_id": hwid,
            "session_id": session_id,
            "app_version": __version__,
        })
        return resp.get("status", "active") == "active"
    except Exception:
        # Network hatası → session'ı kırma, devam et
        return True


def deactivate_device(
    license_key: str,
    hardware_id: Optional[str] = None,
) -> tuple[bool, str]:
    """Bu cihazı lisanstan kaldır (yer açmak için).

    Returns:
        (success, message) tuple.
    """
    hwid = hardware_id or get_hardware_id()

    try:
        resp = _post_json(DEACTIVATE_ENDPOINT, {
            "license_key": license_key.strip().upper(),
            "hardware_id": hwid,
        })

        if resp.get("error"):
            return False, str(resp.get("reason", "Deaktivasyon başarısız."))

        clear_cache()
        return True, str(resp.get("message", "Cihaz başarıyla kaldırıldı."))
    except Exception as exc:
        return False, f"Sunucuya ulaşılamadı: {exc}"
