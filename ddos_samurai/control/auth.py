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


def load_tls_server_credentials(
    cert_path: str,
    key_path: str,
    *,
    client_ca_path: str = "",
    require_client_auth: bool = False,
):
    import grpc

    with open(cert_path, "rb") as cert_file:
        cert = cert_file.read()
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    root_certs = None
    if str(client_ca_path or "").strip():
        with open(client_ca_path, "rb") as ca_file:
            root_certs = ca_file.read()
    return grpc.ssl_server_credentials(
        [(key, cert)],
        root_certificates=root_certs,
        require_client_auth=bool(require_client_auth),
    )


def load_tls_client_credentials(ca_path: str, *, client_cert_path: str = "", client_key_path: str = ""):
    import grpc

    cert_chain = None
    private_key = None
    if str(client_cert_path or "").strip() and str(client_key_path or "").strip():
        with open(client_cert_path, "rb") as cert_file:
            cert_chain = cert_file.read()
        with open(client_key_path, "rb") as key_file:
            private_key = key_file.read()
    if not str(ca_path or "").strip():
        return grpc.ssl_channel_credentials(
            private_key=private_key,
            certificate_chain=cert_chain,
        )
    with open(ca_path, "rb") as ca_file:
        ca = ca_file.read()
    return grpc.ssl_channel_credentials(
        root_certificates=ca,
        private_key=private_key,
        certificate_chain=cert_chain,
    )


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
