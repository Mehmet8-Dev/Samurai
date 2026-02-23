from __future__ import annotations

import logging
from dataclasses import dataclass

from .profile_names import DEFAULT_BROWSER_PROFILE, PROFILE_NONE

# HTTP/2 Settings IDs
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6


@dataclass(frozen=True)
class H2Profile:
    name: str
    settings: dict[int, int]
    window_update: int
    priority: dict[str, int] | None = None


@dataclass(frozen=True)
class AppliedH2Config:
    requested: str
    resolved: str
    applied: bool
    reason: str
    settings: dict[int, int]
    window_update: int
    priority: dict[str, int] | None = None


# Profiles based on Akamai H2 Fingerprinting research
H2_PROFILES: dict[str, H2Profile] = {
    "chrome_120": H2Profile(
        name="chrome_120",
        settings={
            SETTINGS_HEADER_TABLE_SIZE: 65536,
            SETTINGS_ENABLE_PUSH: 0,
            SETTINGS_MAX_CONCURRENT_STREAMS: 1000,
            SETTINGS_INITIAL_WINDOW_SIZE: 6291456,
            SETTINGS_MAX_HEADER_LIST_SIZE: 262144,
        },
        window_update=15663105,
        priority=None,
    ),
    "firefox_120": H2Profile(
        name="firefox_120",
        settings={
            SETTINGS_HEADER_TABLE_SIZE: 65536,
            SETTINGS_MAX_CONCURRENT_STREAMS: 128,
            SETTINGS_INITIAL_WINDOW_SIZE: 12582912,
            SETTINGS_MAX_FRAME_SIZE: 16384,
            SETTINGS_MAX_HEADER_LIST_SIZE: 65536,
        },
        window_update=12517377,
        priority=None,
    ),
    "safari_17": H2Profile(
        name="safari_17",
        settings={
            SETTINGS_HEADER_TABLE_SIZE: 4096,
            SETTINGS_ENABLE_PUSH: 1,
            SETTINGS_MAX_CONCURRENT_STREAMS: 100,
            SETTINGS_INITIAL_WINDOW_SIZE: 2097152,
            SETTINGS_MAX_FRAME_SIZE: 16384,
            SETTINGS_MAX_HEADER_LIST_SIZE: 4294967295,
        },
        window_update=2031617,
        priority=None,
    ),
}


def resolve_h2_profile(name: str | None) -> H2Profile | None:
    raw = str(name or "").strip().lower()
    if not raw:
        return H2_PROFILES[DEFAULT_BROWSER_PROFILE]
    if raw == PROFILE_NONE:
        return None
    profile = H2_PROFILES.get(raw)
    if profile is None:
        raise ValueError(f"Unsupported H2 profile: {name!r}")
    return profile


def get_h2_profile(name: str | None) -> H2Profile:
    profile = resolve_h2_profile(name)
    if profile is None:
        raise ValueError("H2 profile 'none' cannot be resolved to concrete settings")
    return profile


def apply_h2_profile(client, profile_name: str | None) -> AppliedH2Config:
    requested = str(profile_name or PROFILE_NONE).strip().lower() or PROFILE_NONE
    profile = resolve_h2_profile(profile_name)

    if profile is None:
        return AppliedH2Config(
            requested=requested,
            resolved=PROFILE_NONE,
            applied=False,
            reason="profile_disabled",
            settings={},
            window_update=0,
            priority=None,
        )

    # httpx/httpcore do not expose a stable public API to inject custom H2
    # settings per client. Keep this fail-visible instead of silent no-op.
    applied = False
    reason = "unsupported_client"
    if client is not None and hasattr(client, "_transport"):
        reason = "transport_does_not_expose_h2_settings"
    elif client is None:
        reason = "no_client"

    logging.info("H2 profile requested=%s resolved=%s applied=%s reason=%s", requested, profile.name, applied, reason)
    return AppliedH2Config(
        requested=requested,
        resolved=profile.name,
        applied=applied,
        reason=reason,
        settings=dict(profile.settings),
        window_update=int(profile.window_update),
        priority=dict(profile.priority) if isinstance(profile.priority, dict) else None,
    )
