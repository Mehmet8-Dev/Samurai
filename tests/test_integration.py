import unittest
from unittest.mock import AsyncMock, patch

from ddos_samurai import orchestrator


def _base_args():
    return {
        "target": "192.168.1.1",
        "port": 80,
        "count": 100,
        "attack_vector": "basic",
        "protocol": "udp",
        "spoof": True,
        "spoof_mode": "realistic",
        "spoof_subnet": None,
        "spoof_list_file": None,
        "payloads": [],
        "tcp_flags": "S",
        "ttl": None,
        "tos": None,
        "window": None,
        "fragment": False,
        "fragment_size": 800,
        "pad": 0,
        "dns_name": "example.com",
        "dns_qtype": ["A"],
        "dns_edns": False,
        "dns_nord": False,
        "delay": 0,
        "rps": 0,
        "jitter": 0,
        "ramp": 0,
        "verbose": False,
        "compute_backend": "cpu",
        # feature flags
        "ja3_profile": "none",
        "tls_profile": "none",
        "h2_profile": "none",
        "stateful": False,
        "source_port": 0,
        # http-ish placeholders (not used for basic vector)
        "http_scheme": "http",
        "http_verify": "true",
        "http_timeout": 5.0,
        "http_retries": 0,
        "http_concurrency": 10,
        "http_method": "GET",
        "http_path": ["/"],
        "http2_concurrency": 10,
        "slowloris_concurrency": 10,
        "reflector_file": "does-not-matter.txt",
    }


class TestWorkerProcessIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_worker_process_basic_attack_flow_calls_packet_sender(self):
        args = _base_args()

        mock_packet_sender = AsyncMock()
        with patch.object(orchestrator.senders, "packet_sender", mock_packet_sender):
            await orchestrator.worker_process(worker_id=1, args=args, ssl_context=None)
            mock_packet_sender.assert_awaited_once()
