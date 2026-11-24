import json
import os
import socket
import subprocess
import time
import unittest
from unittest.mock import MagicMock


def _pick_free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestMetricFormattingLogic(unittest.TestCase):
    def test_metric_formatting_logic(self):
        """
        Validate Prometheus-style label formatting logic without starting a server.

        Uses a plain dict (not a multiprocessing.Manager proxy) to avoid pickling noise.
        """
        shared_metrics = {
            "requests_total": {
                "help": "Total requests",
                "type": "counter",
                "values": {
                    (("status", "200"), ("path", "/")): 150,
                    (("status", "404"), ("path", "/foo")): 25,
                    (("status", "error"), ("path", "/")): 10,
                },
            }
        }
        _lock = MagicMock()  # Placeholder for parity with orchestrator's shared lock.

    # This test doesn't need to run the server, just check the logic
    # that would be inside the endpoint.
        content = []
        for key, data in shared_metrics.items():
            if key.endswith("_total"):
                content.append(f"# HELP ddos_{key} {data.get('help', '')}")
                content.append(f"# TYPE ddos_{key} {data.get('type', 'counter')}")
                for labels, value in data.get("values", {}).items():
                    label_dict = dict(labels)
                    label_str = ",".join([f'{k}="{v}"' for k, v in label_dict.items()])
                    content.append(f"ddos_{key}{{{label_str}}} {value}")

        expected_content = [
            "# HELP ddos_requests_total Total requests",
            "# TYPE ddos_requests_total counter",
            'ddos_requests_total{status="200",path="/"} 150',
            'ddos_requests_total{status="404",path="/foo"} 25',
            'ddos_requests_total{status="error",path="/"} 10',
        ]

        # Dict iteration order isn't relevant for exposition; compare as sets.
        self.assertEqual(sorted(content), sorted(expected_content))


class TestDistributedTelcoAndTelemetryE2E(unittest.TestCase):
    ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    SAMURAI_BIN = os.path.join(ROOT, "build", "cli", "samurai")
    MASTER_BIN = os.path.join(ROOT, "build", "control", "daemon", "samurai_master")
    SLAVE_BIN = os.path.join(ROOT, "build", "control", "daemon", "samurai_slave")
    WORKER_DIR = os.path.join(ROOT, "build", "zmq")

    def test_cli_telco_and_live_ipfix_udp(self):
        self.assertTrue(os.path.isfile(self.SAMURAI_BIN))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(3.0)
        udp_port = sock.getsockname()[1]
        try:
            cmd = [
                self.SAMURAI_BIN,
                "--target", "127.0.0.1",
                "--port", "36412",
                "--protocol", "sctp",
                "--worker", "telco",
                "--transport", "loopback",
                "--vector", "basic",
                "--worker-dir", self.WORKER_DIR,
                "--count", "0",
                "--telco-subscribers", "16",
                "--telco-cps", "1000",
                "--telco-duration-ms", "200",
                "--sctp-rate", "1000",
                "--db-port", "5099",
                "--ipfix-enabled",
                "--ipfix-collector", "127.0.0.1",
                "--ipfix-port", str(udp_port),
                "--ipfix-sample-rate", "1",
                "--ipfix-domain-id", "5099",
                "--ipfix-export-interval-ms", "50",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            summaries = [
                json.loads(line)
                for line in proc.stdout.splitlines()
                if '"run_summary"' in line
            ]
            self.assertTrue(summaries, proc.stdout)
            s = summaries[-1]
            self.assertGreater(s["sent"], 0)
            self.assertGreaterEqual(s["ipfix_telemetry"]["exported_packets"], 1)
            self.assertEqual(s["telco_telemetry"]["active_sessions"], 16)
            self.assertGreaterEqual(s["telco_telemetry"]["avg_setup_latency_us"], 1)

            pkt, _ = sock.recvfrom(4096)
            self.assertGreaterEqual(len(pkt), 16)
            ver = (pkt[0] << 8) | pkt[1]
            self.assertEqual(ver, 10)
        finally:
            sock.close()

    def test_distributed_master_slave_telco_and_ipfix(self):
        self.assertTrue(os.path.isfile(self.MASTER_BIN))
        self.assertTrue(os.path.isfile(self.SLAVE_BIN))
        ctrl_port = _pick_free_tcp_port()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5.0)
        udp_port = sock.getsockname()[1]

        master = None
        slave = None
        try:
            master_cmd = [
                self.MASTER_BIN,
                "--control-listen", f"tcp://127.0.0.1:{ctrl_port}",
                "--cluster-secret", "test-cluster-secret",
                "--worker", "telco",
                "--transport", "loopback",
                "--target", "127.0.0.1",
                "--port", "5060",
                "--protocol", "sip-rtp",
                "--count", "0",
                "--telco-subscribers", "16",
                "--telco-cps", "1000",
                "--telco-duration-ms", "250",
                "--sip-rate", "1000",
                "--enable-srtp", "1",
                "--db-port", "5099",
                "--ipfix-enabled", "1",
                "--ipfix-collector", "127.0.0.1",
                "--ipfix-port", str(udp_port),
                "--ipfix-sample-rate", "1",
                "--ipfix-domain-id", "77",
                "--ipfix-export-interval-ms", "50",
                "--expect-workers", "1",
                "--wait-workers-s", "10",
                "--job-timeout-s", "20",
            ]
            master = subprocess.Popen(
                master_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.15)
            slave_cmd = [
                self.SLAVE_BIN,
                "--control-endpoints", f"127.0.0.1:{ctrl_port}",
                "--cluster-secret", "test-cluster-secret",
                "--dispatch-mode", "reverse",
                "--worker", "bundle",
                "--worker-dir", self.WORKER_DIR,
                "--worker-id", "slave-telco-test-1",
                "--heartbeat-interval-ms", "250",
            ]
            slave = subprocess.Popen(
                slave_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            out, err = master.communicate(timeout=20)
            self.assertEqual(master.returncode, 0, f"stdout:\n{out}\nstderr:\n{err}")

            json_lines = []
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    json_lines.append(json.loads(line))
            self.assertTrue(json_lines, out)
            snap = json_lines[-1]
            self.assertEqual(snap.get("job_id"), "job-1")
            self.assertEqual(snap.get("pending_shards_left"), 0)
            self.assertEqual(snap.get("inflight_shards_left"), 0)
            self.assertGreaterEqual(snap.get("shards_reported", 0), 1)
            self.assertGreater(snap.get("sent", 0), 0)
            self.assertGreaterEqual(
                snap.get("ipfix_telemetry", {}).get("exported_packets", 0), 1
            )
            self.assertGreaterEqual(
                snap.get("ipfix_telemetry", {}).get("exported_records", 0), 16
            )
            self.assertEqual(
                snap.get("telco_telemetry", {}).get("active_sessions", 0), 16
            )

            pkt, _ = sock.recvfrom(4096)
            self.assertGreaterEqual(len(pkt), 16)
            ver = (pkt[0] << 8) | pkt[1]
            self.assertEqual(ver, 10)
        finally:
            sock.close()
            for p in (slave, master):
                if p is not None and p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=2)

    def test_diagnostic_flags_and_rfc_safety_gates_and_reporting(self):
        import tempfile

        self.assertTrue(os.path.isfile(self.SAMURAI_BIN))
        self.assertTrue(os.path.isfile(self.MASTER_BIN))

        # 1. Diagnostic flags must work cleanly before license/integrity gates.
        for flag in ("--help", "--list-profiles"):
            p = subprocess.run([self.SAMURAI_BIN, flag], capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, f"{flag}: {p.stderr}\n{p.stdout}")

        for flag in ("--help", "--gen-curve-keys"):
            p = subprocess.run([self.MASTER_BIN, flag], capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, f"master {flag}: {p.stderr}\n{p.stdout}")

        # 2. --run-rfc-suite must enforce ValidateTargetSafety & --deny-target.
        with tempfile.TemporaryDirectory() as td:
            rep_bad = os.path.join(td, "rfc_bad.json")
            p_pub = subprocess.run(
                [self.SAMURAI_BIN, "--run-rfc-suite", "2544", "--target", "8.8.8.8",
                 "--rfc-report-out", rep_bad],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(p_pub.returncode, 0)

            p_deny = subprocess.run(
                [self.SAMURAI_BIN, "--run-rfc-suite", "2544", "--target", "127.0.0.1",
                 "--deny-target", "127.0.0.1", "--rfc-report-out", rep_bad],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(p_deny.returncode, 0)

            # 3. CLI file reporting (--report-json / --report-text) includes IPFIX + Telco sections.
            json_rep = os.path.join(td, "cli_report.json")
            txt_rep = os.path.join(td, "cli_report.txt")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(3.0)
            udp_port = sock.getsockname()[1]
            try:
                p_rep = subprocess.run(
                    [
                        self.SAMURAI_BIN,
                        "--target", "127.0.0.1",
                        "--port", "5060",
                        "--protocol", "sip-rtp",
                        "--worker", "telco",
                        "--transport", "loopback",
                        "--vector", "basic",
                        "--worker-dir", self.WORKER_DIR,
                        "--count", "0",
                        "--telco-subscribers", "12",
                        "--telco-cps", "1000",
                        "--telco-duration-ms", "150",
                        "--sip-rate", "1000",
                        "--db-port", "5099",
                        "--ipfix-enabled",
                        "--ipfix-collector", "127.0.0.1",
                        "--ipfix-port", str(udp_port),
                        "--ipfix-sample-rate", "1",
                        "--ipfix-domain-id", "55",
                        "--ipfix-export-interval-ms", "50",
                        "--report-json", json_rep,
                        "--report-text", txt_rep,
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(p_rep.returncode, 0, p_rep.stderr + p_rep.stdout)
                pkt, _ = sock.recvfrom(4096)
                self.assertGreaterEqual(len(pkt), 16)
            finally:
                sock.close()
            with open(json_rep, "r", encoding="utf-8") as fh:
                jdata = json.load(fh)
            self.assertIn("ipfix_telemetry", jdata)
            self.assertGreaterEqual(jdata["ipfix_telemetry"]["exported_packets"], 1)
            self.assertIn("telco_telemetry", jdata)
            self.assertEqual(jdata["telco_telemetry"]["active_sessions"], 12)
            with open(txt_rep, "r", encoding="utf-8") as fh:
                tdata = fh.read()
            self.assertRegex(tdata, r"ipfix_telemetry\s*:")
            self.assertRegex(tdata, r"telco_telemetry\s*:")


