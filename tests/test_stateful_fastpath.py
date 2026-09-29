"""Userspace stateful TCP fast-path (TRex-style) sürücü doğrulaması.

İki in-process (NIC gerektirmeyen) C++ testi çalıştırır:
  * test_stateful_fastpath     -> L4: 3'lü el sıkışma paylaşılan sürücü loop'u
                                  (RX->ingest -> poll -> peek->Send->consume) ile
                                  gerçek TcpDataplaneCore'a karşı tamamlanır.
  * test_stateful_fastpath_l7  -> L7: gerçek run_profile_json (transport=dpdk_direct)
                                  HTTP/1.1 GET -> 200 akışını, sürücünün sahip olduğu
                                  wire üzerinden (kernel-socket'siz) tamamlar.

Bu ikili, DPDK/AF_XDP worker'larının paylaştığı ortak fast-path yolunu doğrular.
"""
import os
import subprocess

import pytest

_BUILD = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "build", "zmq"))


def _run(binary):
    path = os.path.join(_BUILD, binary)
    if not os.path.exists(path):
        pytest.skip(f"{binary} derlenmemiş ({path})")
    res = subprocess.run([path], capture_output=True, text=True, timeout=60)
    return res


def test_stateful_fastpath_l4_handshake():
    res = _run("test_stateful_fastpath")
    assert res.returncode == 0, res.stderr
    assert "ALL STATEFUL FASTPATH DRIVER TESTS PASSED" in res.stdout


def test_stateful_fastpath_l7_http_over_fastpath():
    res = _run("test_stateful_fastpath_l7")
    assert res.returncode == 0, res.stderr
    assert "ALL STATEFUL FASTPATH L7 TESTS PASSED" in res.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
