import types
import sys

import pytest

from ddos_samurai.cli.args import build_parser
from ddos_samurai.cli.validation import _validate_distributed_args


def test_distributed_standalone_noop():
    parser = build_parser()
    args = parser.parse_args(["--role", "standalone"])
    _validate_distributed_args(parser, args)


def test_distributed_slave_endpoint_validation_with_fake_grpc(monkeypatch):
    monkeypatch.setitem(sys.modules, "grpc", types.SimpleNamespace())
    parser = build_parser()
    args = parser.parse_args([
        "--role",
        "slave",
        "--control-endpoints",
        "127.0.0.1:5099,10.0.0.1:5099",
        "--control-insecure",
    ])
    _validate_distributed_args(parser, args)


def test_distributed_master_requires_tls_files_unless_insecure(monkeypatch):
    monkeypatch.setitem(sys.modules, "grpc", types.SimpleNamespace())
    parser = build_parser()
    args = parser.parse_args([
        "--role",
        "master",
    ])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, args)


def test_distributed_heartbeat_bounds(monkeypatch):
    monkeypatch.setitem(sys.modules, "grpc", types.SimpleNamespace())
    parser = build_parser()
    args = parser.parse_args([
        "--role",
        "slave",
        "--control-endpoints",
        "127.0.0.1:5099",
        "--control-insecure",
        "--heartbeat-interval-ms",
        "100",
    ])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, args)


def test_distributed_k8s_port_bounds(monkeypatch):
    import types, sys
    import pytest
    monkeypatch.setitem(sys.modules, 'grpc', types.SimpleNamespace())
    from ddos_samurai.cli.args import build_parser
    from ddos_samurai.cli.validation import _validate_distributed_args
    parser = build_parser()
    args = parser.parse_args(['--role','slave','--control-endpoints','127.0.0.1:5099','--control-insecure','--control-k8s-port','70000'])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, args)
