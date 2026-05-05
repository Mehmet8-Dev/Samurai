"""Distributed control plane — requires ddos_samurai[distributed]."""

from __future__ import annotations

_GRPC_AVAILABLE = False
try:
    import grpc  # noqa: F401

    _GRPC_AVAILABLE = True
except ImportError:
    pass


def require_distributed() -> None:
    if not _GRPC_AVAILABLE:
        raise ImportError(
            "Distributed mode requires grpcio. "
            "Install with: pip install 'ddos_samurai[distributed]'"
        )
