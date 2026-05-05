"""Auth/TLS helpers for distributed control plane."""

from __future__ import annotations

from typing import Optional


def split_endpoints(raw: str) -> list[str]:
    return [ep.strip() for ep in str(raw or "").split(",") if ep.strip()]


def build_cluster_metadata(cluster_secret: str) -> list[tuple[str, str]]:
    secret = str(cluster_secret or "").strip()
    return [("x-cluster-secret", secret)] if secret else []


def validate_cluster_secret(expected: str, provided: Optional[str]) -> bool:
    exp = str(expected or "").strip()
    got = str(provided or "").strip()
    if not exp:
        return True
    return exp == got
