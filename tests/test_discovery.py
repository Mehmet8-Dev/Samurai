import sys
import types

from ddos_samurai.control.discovery import EndpointDiscovery


def test_manual_endpoints_have_priority():
    d = EndpointDiscovery("10.0.0.1:5099,10.0.0.2:5099", prefer_k8s=True)
    out = d.resolve_with_fallback()
    assert out == ["10.0.0.1:5099", "10.0.0.2:5099"]


def test_k8s_fallback_without_dependency_returns_empty(monkeypatch):
    monkeypatch.setitem(sys.modules, "kubernetes", None)
    d = EndpointDiscovery("", prefer_k8s=True)
    assert d.resolve_with_fallback() == []


def test_k8s_fallback_with_fake_client(monkeypatch):
    class _Cond:
        def __init__(self, t, s):
            self.type = t
            self.status = s

    class _Status:
        def __init__(self, ip, phase, ready=True):
            self.pod_ip = ip
            self.phase = phase
            self.conditions = [_Cond("Ready", "True" if ready else "False")]

    class _Pod:
        def __init__(self, ip, phase, ready=True):
            self.status = _Status(ip, phase, ready=ready)

    class _Pods:
        def __init__(self):
            self.items = [
                _Pod("10.1.1.7", "Running", ready=True),
                _Pod("", "Running", ready=True),
                _Pod("10.1.1.8", "Pending", ready=True),
                _Pod("10.1.1.9", "Running", ready=False),
                _Pod("10.1.1.7", "Running", ready=True),
            ]

    class _CoreV1Api:
        def list_namespaced_pod(self, namespace, label_selector=None):
            assert namespace == "lab"
            assert label_selector == "app=worker"
            return _Pods()

    fake_client = types.SimpleNamespace(CoreV1Api=lambda: _CoreV1Api())
    fake_config = types.SimpleNamespace(
        load_incluster_config=lambda: (_ for _ in ()).throw(RuntimeError("not incluster")),
        load_kube_config=lambda: None,
    )
    fake_k8s = types.SimpleNamespace(client=fake_client, config=fake_config)
    monkeypatch.setitem(sys.modules, "kubernetes", fake_k8s)

    d = EndpointDiscovery("", prefer_k8s=True, k8s_namespace="lab", k8s_selector="app=worker", k8s_port=5500)
    assert d.resolve_with_fallback() == ["10.1.1.7:5500"]
