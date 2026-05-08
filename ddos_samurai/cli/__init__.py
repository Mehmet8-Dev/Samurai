"""Modular CLI package preserving the old public surface."""

from __future__ import annotations

from .. import utils
from .args import build_parser
from .helpers import _is_cuda_raw_vector
from .profile_resolver import _resolve_profile_args
from .reporting import build_loss_summary as _build_loss_summary
from .validation import (
    _preflight_l7_capabilities,
    _preflight_lab_profile,
    _preflight_persistent_tx_backend,
    _validate_distributed_args,
    _validate_hybrid_cuda_args,
    _validate_pacing_args,
    _validate_sender_route_args,
)


def main(*args, **kwargs):
    # Keep package import lightweight for parser-only consumers and tests.
    from .app import main as _main

    return _main(*args, **kwargs)


__all__ = [
    "main",
    "build_parser",
    "_validate_pacing_args",
    "_validate_hybrid_cuda_args",
    "_validate_sender_route_args",
    "_validate_distributed_args",
    "_preflight_lab_profile",
    "_preflight_persistent_tx_backend",
    "_preflight_l7_capabilities",
    "_resolve_profile_args",
    "_is_cuda_raw_vector",
    "_build_loss_summary",
    "utils",
]
