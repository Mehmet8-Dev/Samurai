from ddos_samurai import control


def test_lazy_import_guard(monkeypatch):
    monkeypatch.setattr(control, "_GRPC_AVAILABLE", False)
    try:
        control.require_distributed()
        assert False, "require_distributed should fail when grpc is unavailable"
    except ImportError as exc:
        assert "ddos_samurai[distributed]" in str(exc)
