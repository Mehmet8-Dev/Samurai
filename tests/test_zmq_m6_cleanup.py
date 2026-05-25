from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


def test_m6_legacy_files_removed() -> None:
    root = Path(__file__).resolve().parents[1]
    assert not (root / "ddos_samurai" / "senders.py").exists()
    assert not (root / "ddos_samurai" / "dataplane.py").exists()
    assert not (root / "ddos_samurai" / "pacing.py").exists()
    assert not (root / "ddos_samurai" / "_senders").exists()


def test_m6_runtime_guard_no_legacy_cext_imports() -> None:
    for name in [
        "ddos_samurai.fast_sender",
        "ddos_samurai.xdp_sender",
        "ddos_samurai.dataplane_core",
        "ddos_samurai.pacing_engine",
    ]:
        sys.modules.pop(name, None)

    importlib.import_module("ddos_samurai")
    importlib.import_module("ddos_samurai.orchestrator")
    importlib.import_module("ddos_samurai.cli.runtime")
    importlib.import_module("ddos_samurai.control.slave")

    for name in [
        "ddos_samurai.fast_sender",
        "ddos_samurai.xdp_sender",
        "ddos_samurai.dataplane_core",
        "ddos_samurai.pacing_engine",
    ]:
        assert name not in sys.modules, name


def test_m6_worker_process_removed_fail_fast() -> None:
    orchestrator = importlib.import_module("ddos_samurai.orchestrator")
    with pytest.raises(RuntimeError):
        import asyncio

        asyncio.run(orchestrator.worker_process())
