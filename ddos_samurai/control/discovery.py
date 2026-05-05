"""Endpoint discovery abstraction (manual first; K8s later)."""

from __future__ import annotations

from .auth import split_endpoints


class EndpointDiscovery:
    def __init__(self, manual_endpoints: str) -> None:
        self._manual = split_endpoints(manual_endpoints)

    def resolve(self) -> list[str]:
        return list(self._manual)
