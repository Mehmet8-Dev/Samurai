"""Samurai License Client — Abonelik tabanlı lisans doğrulama modülü.

Bu modül, DDoSamurai CLI'nin başlatılması sırasında lisans doğrulaması yapar.
Adobe Creative Cloud / JetBrains modeli: yazılım müşteride çalışır,
aktif abonelik ile lisans sunucusundan doğrulama alır.
"""

from __future__ import annotations

from .client import validate_license, send_heartbeat, deactivate_device
from .features import LicenseResult, Tier, get_tier_features
from .hwid import get_hardware_id

__all__ = [
    "validate_license",
    "send_heartbeat",
    "deactivate_device",
    "LicenseResult",
    "Tier",
    "get_tier_features",
    "get_hardware_id",
]
