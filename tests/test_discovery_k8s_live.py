import os

import pytest

from ddos_samurai.control.discovery import EndpointDiscovery


def test_k8s_live_discovery_smoke():
    if os.getenv("SAMURAI_K8S_LIVE_SMOKE", "0").strip() != "1":
        pytest.skip("set SAMURAI_K8S_LIVE_SMOKE=1 for live cluster smoke")

    namespace = os.getenv("SAMURAI_K8S_NAMESPACE", "default").strip() or "default"
    selector = os.getenv("SAMURAI_K8S_SELECTOR", "").strip()
    port = int(os.getenv("SAMURAI_K8S_PORT", "5099") or "5099")

    d = EndpointDiscovery(
        "",
        prefer_k8s=True,
        k8s_namespace=namespace,
        k8s_selector=selector,
        k8s_port=port,
    )
    eps = d.resolve_with_fallback()
    assert isinstance(eps, list)
    for ep in eps:
        assert ":" in ep
        host, p = ep.rsplit(":", 1)
        assert host
        assert int(p) > 0
