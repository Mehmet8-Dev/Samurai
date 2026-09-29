#!/usr/bin/env python3
"""Minimal real HTTP/2-over-TLS server for e2e tests (ALPN h2).

Same tiny 200-response server as test_h2c_server.py, but wrapped in TLS with a
self-signed cert generated at startup and ALPN advertising "h2". Prints the bound
port as `PORT <n>` on the first stdout line so the harness can read it.
"""
import socket
import ssl
import sys
import tempfile
import threading
import datetime

import h2.config
import h2.connection
import h2.events

BODY = b"hi"


def make_self_signed():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_f.write(cert.public_bytes(serialization.Encoding.PEM))
    key_f.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_f.flush()
    key_f.flush()
    return cert_f.name, key_f.name


def handle(conn):
    config = h2.config.H2Configuration(client_side=False)
    h2conn = h2.connection.H2Connection(config=config)
    h2conn.initiate_connection()
    conn.sendall(h2conn.data_to_send())
    try:
        while True:
            data = conn.recv(65535)
            if not data:
                break
            for event in h2conn.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    sid = event.stream_id
                    h2conn.send_headers(
                        sid,
                        [(":status", "200"), ("content-length", str(len(BODY)))],
                    )
                    h2conn.send_data(sid, BODY, end_stream=True)
            out = h2conn.data_to_send()
            if out:
                conn.sendall(out)
    except (ConnectionError, ssl.SSLError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    cert, key = make_self_signed()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(64)
    print("PORT %d" % sock.getsockname()[1], flush=True)

    while True:
        try:
            raw, _ = sock.accept()
        except OSError:
            break
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            continue
        threading.Thread(target=handle, args=(tls,), daemon=True).start()


if __name__ == "__main__":
    main()
