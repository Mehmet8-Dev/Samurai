import unittest
from unittest.mock import AsyncMock, patch

from ddos_samurai import senders
from ddos_samurai._senders import context as sender_context


class TestSendersFacadeRuntimeForwarding(unittest.IsolatedAsyncioTestCase):
    def test_close_sender_context_is_public_compat_reexport(self):
        self.assertIs(senders.close_sender_context, sender_context.close_sender_context)

    async def test_http2_sender_forwards_httpx_runtime_symbols(self):
        marker_httpx = object()
        with patch.object(senders, "HTTPX_AVAILABLE", True), patch.object(senders, "httpx", marker_httpx):
            with patch("ddos_samurai._senders.l7_http2.http2_sender", new_callable=AsyncMock) as mock_http2:
                mock_http2.return_value = {"attempted": 1, "sent": 1, "errors": 0}
                await senders.http2_sender(
                    target_ip="127.0.0.1",
                    target_port=443,
                    count=1,
                    concurrency=1,
                    http_path="/",
                    http_method="GET",
                    verbose=False,
                )
        kwargs = mock_http2.await_args.kwargs
        self.assertEqual(kwargs["HTTPX_AVAILABLE"], 1)
        self.assertIs(kwargs["httpx_module"], marker_httpx)

    async def test_xdp_sender_forwards_check_xdp_available_symbol(self):
        marker_check = lambda: (True, "ok")
        with patch.object(senders, "check_xdp_available", marker_check):
            with patch("ddos_samurai._senders.l2l3_entry.xdp_sender", new_callable=AsyncMock) as mock_xdp:
                mock_xdp.return_value = {"attempted": 1, "sent": 1, "errors": 0}
                await senders.xdp_sender(
                    packets_buffer=b"\x00" * 48,
                    target_ip="127.0.0.1",
                    target_port=80,
                    count=1,
                    verbose=False,
                )
        kwargs = mock_xdp.await_args.kwargs
        self.assertIs(kwargs["check_xdp_available"], marker_check)

    async def test_quic_sender_forwards_aioquic_runtime_symbols(self):
        marker_connect = object()
        marker_qcfg = object()
        marker_alpn = object()
        marker_h3 = object()
        with patch.object(senders, "AIOQUIC_AVAILABLE", True), patch.object(senders, "connect", marker_connect):
            with patch.object(senders, "QuicConfiguration", marker_qcfg), patch.object(senders, "H3_ALPN", marker_alpn):
                with patch.object(senders, "H3Connection", marker_h3):
                    with patch("ddos_samurai._senders.l7_quic.quic_sender", new_callable=AsyncMock) as mock_quic:
                        mock_quic.return_value = {"attempted": 1, "sent": 1, "errors": 0}
                        await senders.quic_sender(
                            target_ip="127.0.0.1",
                            target_port=443,
                            count=1,
                            concurrency=1,
                            quic_path="/",
                            quic_method="GET",
                            verbose=False,
                        )
        kwargs = mock_quic.await_args.kwargs
        self.assertEqual(kwargs["AIOQUIC_AVAILABLE"], 1)
        self.assertIs(kwargs["connect_fn"], marker_connect)
        self.assertIs(kwargs["QuicConfiguration_cls"], marker_qcfg)
        self.assertIs(kwargs["H3_ALPN_val"], marker_alpn)
        self.assertIs(kwargs["H3Connection_cls"], marker_h3)
