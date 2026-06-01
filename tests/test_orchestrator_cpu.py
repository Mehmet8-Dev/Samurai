from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import patch

from ddos_samurai import orchestrator
from ddos_samurai.zmq.wire import (
    MessageType,
    PacingMode,
    SamuraiWireHeaderV1,
    WorkerKind,
)


class _Counter:
    def __init__(self, value: int = 0):
        self.value = int(value)


class _FakeRuntime:
    def __init__(self, *, fail_launch: bool = False):
        self.fail_launch = bool(fail_launch)

    def launch_worker(self, worker_kind, **kwargs):
        _ = worker_kind
        _ = kwargs
        if self.fail_launch:
            raise RuntimeError("launch_failed")
        return None

    def stop_worker(self, worker_kind, timeout_s: float = 1.0):
        _ = worker_kind
        _ = timeout_s
        return 0


class _FakeDispatcher:
    def dispatch_start_job(self, **kwargs):
        _ = kwargs
        return None

    def dispatch_shutdown_worker(self, **kwargs):
        _ = kwargs
        return None

    def close(self):
        return None


class _FakeTerminalEvent:
    def __init__(self, msg_type: MessageType, payload: dict | None = None):
        self.header = SamuraiWireHeaderV1(
            msg_type=msg_type,
            payload_len=0,
            correlation_id=123,
            worker_kind=WorkerKind.CPU,
            job_id="jid",
        )
        self.payload = b""
        self.payload_decoded = dict(payload or {})
        self.endpoint = "ipc:///tmp/samurai_events_cpu"
        self.last_metric = None


class _FakeCollector:
    def __init__(self, event: _FakeTerminalEvent):
        self._event = event

    def ensure_worker_channel(self, *args, **kwargs):
        _ = args
        _ = kwargs
        return None

    def wait_for_terminal_event(self, **kwargs):
        _ = kwargs
        return self._event

    def close(self):
        return None


def _base_args() -> dict:
    return {
        "target": "127.0.0.1",
        "port": 443,
        "count": 10,
        "attack_vector": "basic",
        "compute_backend": "cpu",
        "protocol": "tcp",
        "scenario_mode": "off",
    }


class TestOrchestratorCpu(unittest.TestCase):
    def test_empty_stats_defaults_to_ok(self):
        stats = orchestrator._empty_stats()
        self.assertEqual(str(stats.get("status")), "ok")

    def test_add_stats_accumulates_core_fields(self):
        acc = orchestrator._empty_stats()
        acc = orchestrator._add_stats(acc, {"attempted": 5, "sent": 4, "errors": 1, "bytes_sent_est": 100})
        acc = orchestrator._add_stats(acc, {"attempted": 3, "sent": 3, "errors": 0, "bytes_sent_est": 80})
        self.assertEqual(int(acc["attempted"]), 8)
        self.assertEqual(int(acc["sent"]), 7)
        self.assertEqual(int(acc["errors"]), 1)
        self.assertEqual(int(acc["bytes_sent_est"]), 180)

    def test_build_pacing_config_from_rps(self):
        cfg = orchestrator._build_pacing_config({"pacing_mode": "rps", "rps": 1234.0, "pin_cpu": -1})
        self.assertEqual(cfg.pacing_mode, PacingMode.RPS)
        self.assertAlmostEqual(float(cfg.target_rps), 1234.0, places=6)
        self.assertEqual(int(cfg.pin_cpu), -1)

    def test_build_pacing_config_promotes_none_to_rps_when_rps_set(self):
        cfg = orchestrator._build_pacing_config({"pacing_mode": "none", "rps": 10.0})
        self.assertEqual(cfg.pacing_mode, PacingMode.RPS)

    def test_resolve_worker_kind_matrix(self):
        self.assertEqual(
            orchestrator._resolve_worker_kind_for_zmq({"compute_backend": "cpu", "attack_vector": "basic"}),
            WorkerKind.CPU,
        )
        self.assertEqual(
            orchestrator._resolve_worker_kind_for_zmq({"compute_backend": "cuda", "attack_vector": "basic"}),
            WorkerKind.GPU,
        )
        self.assertEqual(
            orchestrator._resolve_worker_kind_for_zmq({"compute_backend": "cuda", "attack_vector": "defense"}),
            WorkerKind.DEFENSE,
        )
        self.assertEqual(
            orchestrator._resolve_worker_kind_for_zmq({"compute_backend": "dpdk", "attack_vector": "basic"}),
            WorkerKind.DPDK,
        )
        self.assertEqual(
            orchestrator._resolve_worker_kind_for_zmq({"compute_backend": "af_xdp", "attack_vector": "basic"}),
            WorkerKind.AF_XDP,
        )
        self.assertEqual(
            orchestrator._resolve_worker_kind_for_zmq({"compute_backend": "cpu", "attack_vector": "http"}),
            WorkerKind.L7,
        )
        self.assertEqual(
            orchestrator._resolve_worker_kind_for_zmq({"compute_backend": "cpu", "attack_vector": "http", "scenario_mode": "enforce"}),
            WorkerKind.SCENARIO,
        )

    def test_start_worker_zmq_job_done_event_records_ok(self):
        events: list[dict] = []
        progress = _Counter()
        sent_total = _Counter()
        errors_total = _Counter()

        payload = {"attempted": 10, "sent": 9, "errors": 1, "bytes_sent_est": 576, "status": "ok"}
        fake_event = _FakeTerminalEvent(MessageType.JOB_DONE, payload)

        with patch("ddos_samurai.orchestrator.ZmqRuntimeManager", return_value=_FakeRuntime()), patch(
            "ddos_samurai.orchestrator.ZmqDispatcher", return_value=_FakeDispatcher()
        ), patch("ddos_samurai.orchestrator.ZmqEventCollector", return_value=_FakeCollector(fake_event)), patch(
            "ddos_samurai.orchestrator._snapshot_loss_telemetry", return_value=None
        ):
            orchestrator.start_worker_zmq(
                worker_id=1,
                args=_base_args(),
                progress=progress,
                run_events=events,
                sent_total=sent_total,
                errors_total=errors_total,
            )

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["status"], "ok")
        self.assertEqual(int(ev["stats"]["attempted"]), 10)
        self.assertEqual(int(ev["stats"]["sent"]), 9)
        self.assertEqual(int(ev["stats"]["errors"]), 1)
        self.assertEqual(progress.value, 10)
        self.assertEqual(sent_total.value, 9)
        self.assertEqual(errors_total.value, 1)

    def test_start_worker_zmq_error_event_marks_failed(self):
        events: list[dict] = []
        fake_event = _FakeTerminalEvent(MessageType.ERROR, {"message": "bad"})

        with patch("ddos_samurai.orchestrator.ZmqRuntimeManager", return_value=_FakeRuntime()), patch(
            "ddos_samurai.orchestrator.ZmqDispatcher", return_value=_FakeDispatcher()
        ), patch("ddos_samurai.orchestrator.ZmqEventCollector", return_value=_FakeCollector(fake_event)), patch(
            "ddos_samurai.orchestrator._snapshot_loss_telemetry", return_value=None
        ):
            orchestrator.start_worker_zmq(worker_id=2, args=_base_args(), run_events=events)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "failed")

    def test_start_worker_zmq_launch_exception_marks_failed(self):
        events: list[dict] = []

        with patch("ddos_samurai.orchestrator.ZmqRuntimeManager", return_value=_FakeRuntime(fail_launch=True)), patch(
            "ddos_samurai.orchestrator._snapshot_loss_telemetry", return_value=None
        ):
            orchestrator.start_worker_zmq(worker_id=3, args=_base_args(), run_events=events)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "failed")
        self.assertIn("launch_failed", str(events[0].get("error", "")))

    def test_start_worker_zmq_soak_dispatches_multiple_jobs_until_deadline(self):
        class _LoopDispatcher:
            def __init__(self):
                self.start_calls: list[dict] = []

            def dispatch_start_job(self, **kwargs):
                self.start_calls.append(dict(kwargs))
                return None

            def dispatch_shutdown_worker(self, **kwargs):
                _ = kwargs
                return None

            def close(self):
                return None

        class _LoopCollector:
            def ensure_worker_channel(self, *args, **kwargs):
                _ = args
                _ = kwargs
                return None

            def wait_for_terminal_event(self, **kwargs):
                _ = kwargs
                time.sleep(0.01)
                return _FakeTerminalEvent(
                    MessageType.JOB_DONE,
                    {"attempted": 5, "sent": 5, "errors": 0, "bytes_sent_est": 320, "status": "ok"},
                )

            def close(self):
                return None

        events: list[dict] = []
        progress = _Counter()
        sent_total = _Counter()
        errors_total = _Counter()
        dispatcher = _LoopDispatcher()
        args = _base_args()
        args["soak_deadline_ts"] = float(time.time() + 0.035)

        with patch("ddos_samurai.orchestrator.ZmqRuntimeManager", return_value=_FakeRuntime()), patch(
            "ddos_samurai.orchestrator.ZmqDispatcher", return_value=dispatcher
        ), patch("ddos_samurai.orchestrator.ZmqEventCollector", return_value=_LoopCollector()), patch(
            "ddos_samurai.orchestrator._snapshot_loss_telemetry", return_value=None
        ):
            orchestrator.start_worker_zmq(
                worker_id=4,
                args=args,
                progress=progress,
                run_events=events,
                sent_total=sent_total,
                errors_total=errors_total,
            )

        self.assertGreaterEqual(len(dispatcher.start_calls), 2)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "ok")
        self.assertEqual(progress.value, sent_total.value)
        self.assertGreater(progress.value, 0)
        self.assertEqual(errors_total.value, 0)


class TestOrchestratorWorkerProcess(unittest.IsolatedAsyncioTestCase):
    async def test_worker_process_removed_fail_fast(self):
        with self.assertRaises(RuntimeError):
            await orchestrator.worker_process(worker_id=1, args=_base_args(), ssl_context=None)


if __name__ == "__main__":
    unittest.main()
