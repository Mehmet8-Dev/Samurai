"""CLI adapter for distributed master/slave entrypoints."""

from __future__ import annotations

from ..control.master import run_distributed_master
from ..control.slave import run_distributed_slave

__all__ = ["run_distributed_master", "run_distributed_slave"]
