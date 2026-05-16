import os
import tempfile
import unittest

try:
    import pytest
    pytestmark = [pytest.mark.gpu]
except Exception:  # pragma: no cover - unittest-only environments
    pytestmark = []


class TestGpuPcapGen(unittest.TestCase):
    def test_generate_pcap_small_if_gpu_available(self):
        # Import inside the test so environments without GPU deps can still collect tests.
        from ddos_samurai import gpu_pcap_gen

        ok, msg = gpu_pcap_gen.check_gpu_available()
        if not ok:
            self.skipTest(f"GPU not available: {msg}")

        with tempfile.TemporaryDirectory() as td:
            cfg = gpu_pcap_gen.PcapGenConfig(
                duration_s=1,
                pps=2000,
                mode="mix",
                src_ip="192.168.1.100",
                dst_ip="127.0.0.1",
                tcp_dport=80,
                udp_dport=53,
                chunk_size=2000,
                seed=123,
                flow_count=512,
                realistic=True,
                udp_checksum=False,
                variable_size=True,
                mtu=1500,
                size_profile="mixed",
                output_filename="gpu_pcap_test.pcap",
            )

            try:
                out_path = gpu_pcap_gen.generate_pcap(cfg, project_dir=td)
            except Exception as e:
                msg = str(e)
                if (
                    "CUDA_ERROR_UNSUPPORTED_PTX_VERSION" in msg
                    or "Unsupported .version" in msg
                    or "nvjitlink" in msg.lower()
                    or "nvJitLink" in msg
                    or "may need newer version of nvJitLink library" in msg
                ):
                    self.skipTest("CUDA driver/PTX/nvJitLink mismatch in runtime environment")
                raise
            self.assertTrue(os.path.exists(out_path))

            metrics = gpu_pcap_gen._extract_pcap_metrics(out_path, sample_packets=500)
            self.assertEqual(metrics["invalid_records"], 0)
            self.assertEqual(metrics["packets_total"], cfg.duration_s * cfg.pps)
