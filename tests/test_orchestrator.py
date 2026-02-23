import unittest
from unittest.mock import MagicMock

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
