"""Feature gate enforcement — lisans sonucuna göre engine/vektör kısıtlamaları.

CLI ``run_live_mode()`` öncesinde çağrılır.  Lisans tier'ı ve feature
listesi üzerinden saldırı vektörü, compute backend, süre ve diğer
parametreleri kısıtlar veya reddeder.

Kısıtlama felsefesi:
  - Community  : Sadece basic/http CPU vektörleri, 2 worker, 100PPS, 60s
  - Pro        : GPU, AF_XDP, L7 HTTP/1.1, amplification, spoofing
  - Enterprise : Tümü — HTTP/2, QUIC, WebSocket, Ninja Mode, Prom metrics
"""

from __future__ import annotations

from typing import Optional

from .. import utils
from .features import (
    FEATURE_AF_XDP,
    FEATURE_AMPLIFICATION,
    FEATURE_API_KEY,
    FEATURE_CUSTOM_TCP,
    FEATURE_GPU_ENGINE,
    FEATURE_KPI_GATE,
    FEATURE_KPI_GATE_ADVANCED,
    FEATURE_L7_HTTP11,
    FEATURE_L7_HTTP2,
    FEATURE_L7_QUIC,
    FEATURE_L7_WEBSOCKET,
    FEATURE_NINJA_MODE,
    FEATURE_PCAP_GEN,
    FEATURE_REPORTING_PROM,
    FEATURE_SLOWLORIS,
    FEATURE_SOAK_TESTING,
    FEATURE_SPOOFING,
    LicenseResult,
    has_feature,
)

# ── Vektör → Feature Mapping ───────────────────────────────────────────────

# Hangi attack_vector hangi feature'ı gerektirir?
_VECTOR_FEATURE_MAP: dict[str, str] = {
    "http": FEATURE_L7_HTTP11,
    "http2": FEATURE_L7_HTTP2,
    "quic": FEATURE_L7_QUIC,
    "websocket": FEATURE_L7_WEBSOCKET,
    "slowloris": FEATURE_SLOWLORIS,
    "ntp-amp": FEATURE_AMPLIFICATION,
    "ssdp-amp": FEATURE_AMPLIFICATION,
    "dns-amp": FEATURE_AMPLIFICATION,
    "memcached-amp": FEATURE_AMPLIFICATION,
    "ldap-amp": FEATURE_AMPLIFICATION,
}

# Community tier'da izin verilen vektörler (feature gerekmez)
_COMMUNITY_ALLOWED_VECTORS = {"basic", "dns"}


# ── Enforcement ─────────────────────────────────────────────────────────────


class LicenseGateError(Exception):
    """Feature gate tarafından reddedildi."""

    def __init__(self, message: str, upgrade_hint: str = ""):
        self.message = message
        self.upgrade_hint = upgrade_hint
        super().__init__(message)


def enforce_feature_gates(args, license_result: LicenseResult) -> list[str]:
    """Tüm feature gate kontrollerini çalıştır.

    Engine seçimi, vektör, backend ve parametre kısıtlamalarını uygular.
    Uyumsuzluk varsa ``LicenseGateError`` fırlatır.
    Uyarılar varsa string listesi döndürür.

    Args:
        args: Parsed CLI argümanları.
        license_result: Doğrulanmış lisans sonucu.

    Returns:
        Uyarı mesajları listesi.

    Raises:
        LicenseGateError: Kısıtlama ihlali.
    """
    warnings: list[str] = []
    features = license_result.features or []

    attack_vector = str(getattr(args, "attack_vector", "basic") or "basic").strip().lower()
    compute_backend = str(getattr(args, "compute_backend", "cpu") or "cpu").strip().lower()

    # ── 1. Vektör Kontrolü ──────────────────────────────────────────────

    required_feature = _VECTOR_FEATURE_MAP.get(attack_vector)

    if required_feature:
        if not has_feature(license_result, required_feature):
            raise LicenseGateError(
                f"'{attack_vector}' saldırı vektörü '{required_feature}' "
                f"özelliğini gerektirir. Mevcut tier: {license_result.tier.value}.",
                upgrade_hint=_upgrade_hint(required_feature),
            )
    elif attack_vector not in _COMMUNITY_ALLOWED_VECTORS:
        # Bilinmeyen vektör ama community'de değil — kontrol et
        if not features:
            raise LicenseGateError(
                f"'{attack_vector}' vektörü Community planında desteklenmiyor.",
                upgrade_hint="Pro veya Enterprise plana yükseltin.",
            )

    # ── 2. Compute Backend Kontrolü ─────────────────────────────────────

    if compute_backend == "cuda":
        if not has_feature(license_result, FEATURE_GPU_ENGINE):
            raise LicenseGateError(
                "CUDA/GPU engine Pro veya Enterprise plan gerektirir.",
                upgrade_hint="GPU hızlandırma için Pro plana yükseltin.",
            )

    # ── 3. AF_XDP / Custom TCP Kontrolü ─────────────────────────────────

    xdp_enable = bool(getattr(args, "xdp_enable", False))
    xdp_interface = str(getattr(args, "xdp_interface", "") or "").strip()
    custom_tcp_mode = str(getattr(args, "custom_tcp_mode", "off") or "off").strip().lower()

    # AF_XDP gate: yalnızca kullanıcı XDP'yi açıkça etkinleştirdiyse kontrol et
    if (xdp_enable or xdp_interface) and not has_feature(license_result, FEATURE_AF_XDP):
        raise LicenseGateError(
            "AF_XDP sender backend Pro veya Enterprise plan gerektirir.",
            upgrade_hint="Yüksek performanslı ağ yolu için Pro plana yükseltin.",
        )

    if custom_tcp_mode in ("auto", "required") and not has_feature(license_result, FEATURE_CUSTOM_TCP):
        raise LicenseGateError(
            "Custom TCP stack Pro veya Enterprise plan gerektirir.",
            upgrade_hint="Stateful L7 engine için Pro plana yükseltin.",
        )

    # ── 4. Ninja Mode Kontrolü ──────────────────────────────────────────

    if bool(getattr(args, "ninja_mode", False)) and not has_feature(license_result, FEATURE_NINJA_MODE):
        raise LicenseGateError(
            "Ninja Mode (WAF Bypass) Enterprise plan gerektirir.",
            upgrade_hint="Gelişmiş WAF bypass için Enterprise plana yükseltin.",
        )

    # ── 5. Spoofing Kontrolü ────────────────────────────────────────────

    spoof_enabled = (
        bool(getattr(args, "spoof", False))
        or bool(getattr(args, "realistic_spoof", False))
        or str(getattr(args, "spoof_subnet", "") or "").strip()
        or str(getattr(args, "spoof_list_file", "") or "").strip()
        or str(getattr(args, "spoof_ip", "") or "").strip()
    )
    if spoof_enabled and not has_feature(license_result, FEATURE_SPOOFING):
        raise LicenseGateError(
            "IP spoofing Pro veya Enterprise plan gerektirir.",
            upgrade_hint="Source IP spoofing için Pro plana yükseltin.",
        )

    # ── 6. PCAP Generation Kontrolü ─────────────────────────────────────

    if attack_vector == "pcap-replay" and not has_feature(license_result, FEATURE_PCAP_GEN):
        raise LicenseGateError(
            "PCAP replay/generation Pro veya Enterprise plan gerektirir.",
            upgrade_hint="PCAP özelliği için Pro plana yükseltin.",
        )

    # ── 7. KPI Gate Kontrolü ────────────────────────────────────────────

    kpi_gate_profile = str(getattr(args, "kpi_gate_profile", "off") or "off").strip().lower()
    kpi_hard_fail = bool(getattr(args, "kpi_hard_fail", False))

    if kpi_gate_profile != "off" and not has_feature(license_result, FEATURE_KPI_GATE):
        raise LicenseGateError(
            "KPI Gate Pro veya Enterprise plan gerektirir.",
            upgrade_hint="Performans gating için Pro plana yükseltin.",
        )

    if kpi_gate_profile == "dedicated_lab" and not has_feature(license_result, FEATURE_KPI_GATE_ADVANCED):
        raise LicenseGateError(
            "Dedicated Lab KPI profili Enterprise plan gerektirir.",
            upgrade_hint="Dedicated lab profili için Enterprise plana yükseltin.",
        )

    # ── 8. Soak Testing Kontrolü ────────────────────────────────────────

    fault_scenarios = getattr(args, "fault_inject", None) or []
    if fault_scenarios and not has_feature(license_result, FEATURE_SOAK_TESTING):
        raise LicenseGateError(
            "Soak/fault injection testing Pro veya Enterprise plan gerektirir.",
            upgrade_hint="Dayanıklılık testi için Pro plana yükseltin.",
        )

    # ── 9. Prometheus Metrics Kontrolü ──────────────────────────────────

    prom_textfile = str(getattr(args, "prom_textfile", "") or "").strip()
    if prom_textfile and not has_feature(license_result, FEATURE_REPORTING_PROM):
        warnings.append(
            "Prometheus metrics çıktısı Enterprise plan gerektirir. "
            "--prom-textfile yoksayılıyor."
        )
        args.prom_textfile = ""

    # ── 10. Süre Limiti ─────────────────────────────────────────────────

    if license_result.limits and license_result.limits.max_duration_s > 0:
        requested_duration = int(getattr(args, "duration", 0) or 0)
        max_dur = license_result.limits.max_duration_s
        if requested_duration > max_dur or requested_duration <= 0:
            warnings.append(
                f"Süre lisans limitine ({max_dur}s) düşürüldü. (İstenen: {requested_duration}s)"
            )
            args.duration = max_dur

    # ── 11. PPS Limiti ──────────────────────────────────────────────────

    if license_result.limits and license_result.limits.max_pps > 0:
        requested_rps = float(getattr(args, "rps", 0.0) or 0.0)
        max_pps = float(license_result.limits.max_pps)
        if requested_rps > max_pps:
            warnings.append(
                f"PPS lisans limitine ({int(max_pps)}) düşürüldü. (İstenen: {int(requested_rps)})"
            )
            args.rps = max_pps

    return warnings


def _upgrade_hint(feature: str) -> str:
    """Feature'a göre yükseltme önerisi."""
    enterprise_only = {
        FEATURE_L7_HTTP2, FEATURE_L7_QUIC, FEATURE_L7_WEBSOCKET,
        FEATURE_NINJA_MODE, FEATURE_KPI_GATE_ADVANCED, FEATURE_REPORTING_PROM,
        FEATURE_API_KEY,
    }
    if feature in enterprise_only:
        return "Bu özellik Enterprise plana özeldir. https://ddosamurai.com/fiyatlandirma"
    return "Bu özellik Pro veya Enterprise plana yükseltme gerektirir. https://ddosamurai.com/fiyatlandirma"
