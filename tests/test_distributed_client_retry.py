import socket

import pytest

from ddos_samurai.control.client import SlaveControlClient
from ddos_samurai.control.server import MasterControlServer


def _grpc_or_skip():
    return pytest.importorskip("grpc")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = int(s.getsockname()[1])
    s.close()
    return p


def test_client_retries_next_endpoint_when_first_unreachable():
    _grpc_or_skip()
    bad_port = _free_port()
    good_port = _free_port()
    server = MasterControlServer(f"127.0.0.1:{good_port}", insecure=True)
    server.start()
    try:
        endpoints = f"127.0.0.1:{bad_port},127.0.0.1:{good_port}"
        client = SlaveControlClient(endpoints, insecure=True)
        reg = client.register_worker("w-retry-1", "w-retry-1", {})
        assert reg["accepted"] is True
    finally:
        server.stop(0.0)
