import time
from pathlib import Path

import pytest

from ddos_samurai.control.server import MasterControlServer


pytest.importorskip("grpc")


def test_tls_watcher_detects_file_change_and_triggers_restart(tmp_path, monkeypatch):
    cert = Path(tmp_path) / "tls.crt"
    key = Path(tmp_path) / "tls.key"
    ca = Path(tmp_path) / "ca.crt"
    cert.write_text("old-cert", encoding="utf-8")
    key.write_text("old-key", encoding="utf-8")
    ca.write_text("old-ca", encoding="utf-8")

    server = MasterControlServer(
        listen_addr="127.0.0.1:5099",
        insecure=False,
        tls_cert=str(cert),
        tls_key=str(key),
        tls_client_ca=str(ca),
        tls_watch_files=True,
        tls_reload_interval_s=0.1,
    )

    called = {"n": 0}

    def _fake_restart():
        called["n"] += 1
        server._tls_mtime = server._current_tls_mtime()
        return True

    monkeypatch.setattr(server, "_restart_tls_server", _fake_restart)
    server.running = True
    server._tls_mtime = server._current_tls_mtime()
    server._start_tls_watcher()
    try:
        time.sleep(0.15)
        cert.write_text("new-cert", encoding="utf-8")
        deadline = time.time() + 2.0
        while time.time() < deadline and int(called["n"]) < 1:
            time.sleep(0.05)
        assert int(called["n"]) >= 1
    finally:
        server.running = False
        server._stop_tls_watcher()
