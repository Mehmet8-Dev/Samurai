"""Auth/TLS helpers for distributed control plane."""

from __future__ import annotations

import os
from typing import Optional


def split_endpoints(raw: str) -> list[str]:
    return [ep.strip() for ep in str(raw or "").split(",") if ep.strip()]


def build_cluster_metadata(cluster_secret: str) -> list[tuple[str, str]]:
    secret = str(cluster_secret or "").strip()
    return [("x-cluster-secret", secret)] if secret else []


def validate_cluster_secret(expected: str, provided: Optional[str]) -> bool:
    exp = str(expected or "").strip()
    got = str(provided or "").strip()
    if not exp:
        return True
    return exp == got


def load_tls_server_credentials(cert_path: str, key_path: str):
    import grpc

    with open(cert_path, "rb") as cert_file:
        cert = cert_file.read()
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    return grpc.ssl_server_credentials([(key, cert)])


def load_tls_client_credentials(ca_path: str):
    import grpc

    with open(ca_path, "rb") as ca_file:
        ca = ca_file.read()
    return grpc.ssl_channel_credentials(root_certificates=ca)


def ensure_tls_files_exist(*paths: str) -> None:
    for path in paths:
        if path and not os.path.isfile(path):
            raise FileNotFoundError(path)


def client_call_credentials(cluster_secret: str):
    import grpc

    class _SecretPlugin(grpc.AuthMetadataPlugin):
        def __init__(self, secret: str) -> None:
            self._secret = str(secret or "").strip()

        def __call__(self, context, callback):
            _ = context
            md = []
            if self._secret:
                md.append(("x-cluster-secret", self._secret))
            callback(md, None)

    return grpc.metadata_call_credentials(_SecretPlugin(cluster_secret))
