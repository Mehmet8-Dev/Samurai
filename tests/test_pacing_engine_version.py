#!/usr/bin/env python3
import pytest


def _require_pacing_engine():
    from ddos_samurai.pacing import PACING_ENGINE_AVAILABLE
    if not PACING_ENGINE_AVAILABLE:
        pytest.skip("pacing_engine C extension not available in this environment.")


def test_check_capabilities_exposes_tpacket_v3():
    _require_pacing_engine()
    from ddos_samurai.pacing import check_capabilities

    caps = check_capabilities() or {}
    assert "tpacket_v3" in caps
    assert int(caps.get("tpacket_v3", 0) or 0) in (0, 1)


def test_stats_schema_includes_txring_packet_version_fields():
    _require_pacing_engine()
    from ddos_samurai.pacing import get_stats

    stats = get_stats() or {}
    assert "txring_packet_version" in stats
    assert "txring_packet_version_name" in stats
    assert isinstance(stats.get("txring_packet_version_name"), str)

