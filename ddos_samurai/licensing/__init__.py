"""Samurai License Client — Abonelik tabanlı lisans doğrulama modülü.

Bu modül, DDoSamurai CLI'nin başlatılması sırasında lisans doğrulaması yapar.
Adobe Creative Cloud / JetBrains modeli: yazılım müşteride çalışır,
aktif abonelik ile lisans sunucusundan doğrulama alır.
"""

from __future__ import annotations

from .client import validate_license, send_heartbeat, deactivate_device
from .features import LicenseResult, Tier, get_tier_features, has_feature
from .gates import enforce_feature_gates, LicenseGateError
from .hwid import get_hardware_id

__all__ = [
    "validate_license",
    "send_heartbeat",
    "deactivate_device",
    "enforce_feature_gates",
    "LicenseGateError",
    "LicenseResult",
    "Tier",
    "get_tier_features",
    "has_feature",
    "get_hardware_id",
]
