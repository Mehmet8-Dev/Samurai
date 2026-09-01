#!/usr/bin/env python3
"""Minimal real HTTP/2 cleartext (h2c prior-knowledge) server for e2e tests.

Uses the Hyper `h2` protocol stack (a real, spec-compliant HTTP/2 implementation)
over plain TCP -- the client speaks the HTTP/2 connection preface immediately, no
Upgrade dance. Binds an ephemeral loopback port and prints it as `PORT <n>` on the
first stdout line so the test harness can read it. Serves a tiny 200 response to
every request stream until terminated.
"""
import socket
import sys
import threading

import h2.config
import h2.connection
import h2.events

BODY = b"hi"


def handle(conn: socket.socket) -> None:
    config = h2.config.H2Configuration(client_side=False)
    h2conn = h2.connection.H2Connection(config=config)
    h2conn.initiate_connection()
    conn.sendall(h2conn.data_to_send())
    try:
        while True:
            data = conn.recv(65535)
            if not data:
                break
            events = h2conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    sid = event.stream_id
                    h2conn.send_headers(
                        sid,
                        [
                            (":status", "200"),
                            ("content-length", str(len(BODY))),
                            ("content-type", "text/plain"),
                        ],
                    )
                    h2conn.send_data(sid, BODY, end_stream=True)
            out = h2conn.data_to_send()
            if out:
                conn.sendall(out)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(128)
    port = srv.getsockname()[1]
    print(f"PORT {port}", flush=True)
    try:
        while True:
            client, _ = srv.accept()
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=handle, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
