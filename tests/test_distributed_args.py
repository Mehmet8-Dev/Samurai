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


def test_distributed_management_api_requires_token_when_enabled(monkeypatch):
    monkeypatch.setitem(sys.modules, "grpc", types.SimpleNamespace())
    parser = build_parser()
    args = parser.parse_args([
        "--role",
        "master",
        "--control-insecure",
        "--management-api-enable",
    ])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, args)


def test_distributed_autoscale_requires_target_name(monkeypatch):
    monkeypatch.setitem(sys.modules, "grpc", types.SimpleNamespace())
    parser = build_parser()
    args = parser.parse_args([
        "--role",
        "master",
        "--control-insecure",
        "--control-autoscale-enable",
    ])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, args)


def test_distributed_tenant_namespace_validation(monkeypatch):
    monkeypatch.setitem(sys.modules, "grpc", types.SimpleNamespace())
    parser = build_parser()
    bad = parser.parse_args([
        "--role",
        "master",
        "--control-insecure",
        "--tenant-namespace",
        "bad/tenant",
    ])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, bad)

    good = parser.parse_args([
        "--role",
        "master",
        "--control-insecure",
        "--tenant-namespace",
        "tenant_a-1",
    ])
    _validate_distributed_args(parser, good)


def test_distributed_region_validation(monkeypatch):
    monkeypatch.setitem(sys.modules, "grpc", types.SimpleNamespace())
    parser = build_parser()
    bad = parser.parse_args([
        "--role",
        "master",
        "--control-insecure",
        "--worker-region",
        "bad/region",
    ])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, bad)

    bad_factor = parser.parse_args([
        "--role",
        "master",
        "--control-insecure",
        "--cross-region-heartbeat-factor",
        "0.9",
    ])
    with pytest.raises(SystemExit):
        _validate_distributed_args(parser, bad_factor)
