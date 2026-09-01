#!/usr/bin/env python3
"""Minimal real HTTP/3 server for e2e tests, backed by aioquic.

aioquic is a real, spec-compliant QUIC + HTTP/3 implementation. This server binds
an ephemeral loopback UDP port, negotiates QUIC/TLS1.3 with ALPN "h3", and answers
every request stream with a tiny 200 response. It generates its own self-signed
certificate in-process (the client runs with verify=0, so the cert is not checked).

Prints `PORT <n>` on the first stdout line so the test harness can read the port.
"""
import asyncio
import datetime
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BODY = b"hi"


def self_signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


class H3Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._http is None:
            self._http = H3Connection(self._quic)
        for h3_event in self._http.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                sid = h3_event.stream_id
                self._http.send_headers(
                    stream_id=sid,
                    headers=[
                        (b":status", b"200"),
                        (b"content-length", str(len(BODY)).encode()),
                        (b"content-type", b"text/plain"),
                    ],
                )
                self._http.send_data(stream_id=sid, data=BODY, end_stream=True)
        self.transmit()


async def main() -> int:
    cert, key = self_signed()
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    config.certificate = cert
    config.private_key = key

    server = await serve("127.0.0.1", 0, configuration=config, create_protocol=H3Server)
    # aioquic's serve() returns a QuicServer whose _transport holds the bound socket.
    port = server._transport.get_extra_info("sockname")[1]
    print(f"PORT {port}", flush=True)
    await asyncio.Future()  # run forever
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        pass
