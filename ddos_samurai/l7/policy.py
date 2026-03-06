from __future__ import annotations


_ENGINE_CHOICES = {"python", "c_state"}
_FALLBACK_POLICIES = {"allow", "fail"}
_DEDICATED_KPI_PROFILES = {"dedicated_lab"}


def normalize_engine(name: str | None, *, allow_auto: bool = False, default: str = "python") -> str:
    raw = str(name if name is not None else default).strip().lower()
    if allow_auto and raw == "auto":
        return "auto"
    if raw in {"c", "state", "cstate"}:
        return "c_state"
    if raw in _ENGINE_CHOICES:
        return raw
    return str(default if default in _ENGINE_CHOICES or (allow_auto and default == "auto") else "python")


def normalize_fallback_policy(name: str | None) -> str:
    raw = str(name or "allow").strip().lower()
    if raw in _FALLBACK_POLICIES:
        return raw
    return "allow"


def is_dedicated_profile(*, lab_profile: str | None, kpi_gate_profile: str | None = None) -> bool:
    lp = str(lab_profile or "off").strip().lower()
    kp = str(kpi_gate_profile or "off").strip().lower()
    return lp == "dedicated" or kp in _DEDICATED_KPI_PROFILES


def resolve_capability_strict(
    *,
    capability_strict: bool,
    lab_profile: str | None,
    kpi_gate_profile: str | None = None,
) -> bool:
    if bool(capability_strict):
        return True
    return is_dedicated_profile(lab_profile=lab_profile, kpi_gate_profile=kpi_gate_profile)


def allow_python_fallback(
    *,
    fallback_policy: str | None,
    capability_strict: bool,
    legacy_path_enable: bool = True,
) -> bool:
    if bool(capability_strict):
        return False
    if normalize_fallback_policy(fallback_policy) == "fail":
        return False
    return bool(legacy_path_enable)

