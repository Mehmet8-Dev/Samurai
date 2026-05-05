import pytest

from ddos_samurai.control.auth import (
    build_cluster_metadata,
    split_endpoints,
    validate_cluster_secret,
    load_tls_client_credentials,
)


def test_split_endpoints_and_metadata():
    assert split_endpoints("a:1,b:2") == ["a:1", "b:2"]
    assert build_cluster_metadata("sekret") == [("x-cluster-secret", "sekret")]


def test_cluster_secret_validation():
    assert validate_cluster_secret("", "anything") is True
    assert validate_cluster_secret("abc", "abc") is True
    assert validate_cluster_secret("abc", "xyz") is False


def test_tls_client_credentials_default_root_ca_if_grpc_available():
    grpc = pytest.importorskip("grpc")
    creds = load_tls_client_credentials("")
    assert isinstance(creds, grpc.ChannelCredentials)
