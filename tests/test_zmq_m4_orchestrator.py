from __future__ import annotations

from unittest.mock import patch

from ddos_samurai import orchestrator


def test_start_worker_delegates_to_zmq_path() -> None:
    with patch("ddos_samurai.orchestrator.start_worker_zmq", return_value=None) as m:
        orchestrator.start_worker(
            worker_id=7,
            args={"target": "127.0.0.1", "port": 443, "count": 1},
            progress=None,
            progress_lock=None,
            tls_profile="none",
            run_events=[],
            sent_total=None,
            errors_total=None,
            resource_stats=None,
        )
    assert m.called
    kwargs = m.call_args.kwargs
    assert kwargs["tls_profile"] == "none"
