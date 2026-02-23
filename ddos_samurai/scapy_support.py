"""Scapy import helper.

Scapy performs privileged/OS-specific discovery at import time on some platforms.
In restricted environments (CI/sandbox), importing scapy may raise PermissionError.

We keep scapy imports lazy and behind a small shim so the rest of the codebase
remains importable for unit tests and non-packet features.
"""

from __future__ import annotations

import functools
from typing import Any, Optional, Tuple


class ScapyUnavailableError(RuntimeError):
    """Raised when scapy is required but cannot be imported/initialized."""


@functools.lru_cache(maxsize=1)
def _try_import_scapy() -> Tuple[Optional[Any], Optional[BaseException]]:
    try:
        import scapy.all as scapy  # type: ignore

        return scapy, None
    except BaseException as e:  # pragma: no cover (varies by environment)
        return None, e


def is_scapy_available() -> bool:
    scapy, _err = _try_import_scapy()
    return scapy is not None


def require_scapy() -> Any:
    """Return scapy module, or raise ScapyUnavailableError with context."""
    scapy, err = _try_import_scapy()
    if scapy is None:
        msg = "Scapy is unavailable in this environment (import/initialize failed)."
        raise ScapyUnavailableError(msg) from err
    return scapy

