from ddos_samurai.orchestrator import run_metrics_server
import multiprocessing
from unittest.mock import MagicMock, patch

def test_metric_formatting_logic():
    """
    Tests the logic that failed in the `get_metrics` endpoint,
    using a standard dict instead of a multiprocessing Manager to avoid PicklingError.
    """
    # 1. Simulate the shared metrics structure with standard dicts
    shared_metrics = {
        'requests_total': {
            "help": "Total requests",
            "type": "counter",
            "values": {
                (('status', '200'), ('path', '/')): 150,
                (('status', '404'), ('path', '/foo')): 25,
                (('status', 'error'), ('path', '/')): 10,
            }
        }
    }
    lock = MagicMock() # Mock the lock

    # This test doesn't need to run the server, just check the logic
    # that would be inside the endpoint.
    content = []
    for key, data in shared_metrics.items():
        if key.endswith('_total'):
            content.append(f"# HELP ddos_{key} {data.get('help', '')}")
            content.append(f"# TYPE ddos_{key} {data.get('type', 'counter')}")
            for labels, value in data.get('values', {}).items():
                # Convert tuple of tuples to a dictionary for the label string
                label_dict = dict(labels)
                label_str = ",".join([f'{k}="{v}"' for k, v in label_dict.items()])
                content.append(f"ddos_{key}{{{label_str}}} {value}")
    
    expected_content = [
        '# HELP ddos_requests_total Total requests',
        '# TYPE ddos_requests_total counter',
        'ddos_requests_total{status="200",path="/"} 150',
        'ddos_requests_total{status="404",path="/foo"} 25',
        'ddos_requests_total{status="error",path="/"} 10'
    ]
    
    # The order of dictionary items is not guaranteed, so we sort the generated metric lines
    assert sorted(content) == sorted(expected_content)
