"""Tier definitions and feature-gate mapping.

Her abonelik tier'ı (community / pro / enterprise) hangi engine ve
özellik setine erişebileceğini burada tanımlar.  CLI tarafından
``LicenseResult.features`` listesi üzerinden kontrol edilir.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Tier(str, enum.Enum):
    """Abonelik katmanları."""

    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class TierLimits:
    """Tier'a özgü sayısal limitler."""

    max_workers: int
    max_pps: int  # 0 = sınırsız
    max_duration_s: int  # 0 = sınırsız
    max_devices: int


@dataclass
class LicenseResult:
    """Lisans doğrulama sonucu — CLI bu objeyi kullanır."""

    valid: bool
    tier: Tier = Tier.COMMUNITY
    features: list[str] = field(default_factory=list)
    limits: Optional[TierLimits] = None
    expires: str = ""
    customer_email: str = ""
    reason: str = ""
    session_id: str = ""
    offline: bool = False  # Offline cache'ten mi geldi?


# ── Feature Tanımları ───────────────────────────────────────────────────────

FEATURE_GPU_ENGINE = "gpu_engine"
FEATURE_AF_XDP = "af_xdp"
FEATURE_L7_HTTP11 = "l7_http11"
FEATURE_L7_HTTP2 = "l7_http2"
FEATURE_L7_QUIC = "l7_quic"
FEATURE_L7_WEBSOCKET = "l7_websocket"
FEATURE_CUSTOM_TCP = "custom_tcp"
FEATURE_PCAP_GEN = "pcap_gen"
FEATURE_KPI_GATE = "kpi_gate"
FEATURE_KPI_GATE_ADVANCED = "kpi_gate_advanced"
FEATURE_REPORTING_JSON = "reporting_json"
FEATURE_REPORTING_MD = "reporting_md"
FEATURE_REPORTING_PROM = "reporting_prom"
FEATURE_SOAK_TESTING = "soak_testing"
FEATURE_NINJA_MODE = "ninja_mode"
FEATURE_AMPLIFICATION = "amplification"
FEATURE_SPOOFING = "spoofing"
FEATURE_SLOWLORIS = "slowloris"
FEATURE_API_KEY = "api_key"

# ── Tier → Feature Mapping ──────────────────────────────────────────────────

_COMMUNITY_FEATURES: list[str] = [
    # Temel vektörler
    # basic, http — sadece CPU, kısıtlı
]

_PRO_FEATURES: list[str] = [
    FEATURE_GPU_ENGINE,
    FEATURE_AF_XDP,
    FEATURE_L7_HTTP11,
    FEATURE_CUSTOM_TCP,
    FEATURE_PCAP_GEN,
    FEATURE_KPI_GATE,
    FEATURE_REPORTING_JSON,
    FEATURE_REPORTING_MD,
    FEATURE_SOAK_TESTING,
    FEATURE_AMPLIFICATION,
    FEATURE_SPOOFING,
    FEATURE_SLOWLORIS,
]

_ENTERPRISE_FEATURES: list[str] = [
    *_PRO_FEATURES,
    FEATURE_L7_HTTP2,
    FEATURE_L7_QUIC,
    FEATURE_L7_WEBSOCKET,
    FEATURE_KPI_GATE_ADVANCED,
    FEATURE_REPORTING_PROM,
    FEATURE_NINJA_MODE,
    FEATURE_API_KEY,
]

_TIER_FEATURES: dict[Tier, list[str]] = {
    Tier.COMMUNITY: _COMMUNITY_FEATURES,
    Tier.PRO: _PRO_FEATURES,
    Tier.ENTERPRISE: _ENTERPRISE_FEATURES,
}

_TIER_LIMITS: dict[Tier, TierLimits] = {
    Tier.COMMUNITY: TierLimits(
        max_workers=2,
        max_pps=100,
        max_duration_s=60,
        max_devices=1,
    ),
    Tier.PRO: TierLimits(
        max_workers=16,
        max_pps=0,  # sınırsız
        max_duration_s=0,
        max_devices=3,
    ),
    Tier.ENTERPRISE: TierLimits(
        max_workers=0,  # sınırsız
        max_pps=0,
        max_duration_s=0,
        max_devices=10,
    ),
}


def get_tier_features(tier: Tier) -> list[str]:
    """Tier'a ait feature listesini döndür."""
    return list(_TIER_FEATURES.get(tier, _COMMUNITY_FEATURES))


def get_tier_limits(tier: Tier) -> TierLimits:
    """Tier'a ait limitleri döndür."""
    return _TIER_LIMITS.get(tier, _TIER_LIMITS[Tier.COMMUNITY])


def has_feature(result: LicenseResult, feature: str) -> bool:
    """Lisans sonucunun belirtilen özelliğe sahip olup olmadığını kontrol et."""
    return feature in (result.features or [])
