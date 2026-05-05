from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import random
import socket
import time
from typing import Any


_TCP_STATE_MAP: dict[int, str] = {
    0: "closed",
    1: "syn_sent",
    2: "syn_ack_rcvd",
    3: "established",
    4: "fin_wait",
    5: "time_wait",
    6: "rst_seen",
}


def _ip_to_u32(ip_text: str) -> int:
    return int(ipaddress.IPv4Address(str(ip_text).strip()))


def _resolve_ipv4(host_or_ip: str) -> str:
    s = str(host_or_ip or "").strip()
    if not s:
        raise ValueError("target_ip must be a non-empty IPv4 or hostname")
    try:
        ipaddress.IPv4Address(s)
        return s
    except Exception:
        return socket.gethostbyname(s)


def _guess_source_ipv4(dst_ip: str) -> str:
    # Best-effort source IP resolution for outbound route.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((str(dst_ip), 9))
        local_ip = str(probe.getsockname()[0] or "").strip()
        if local_ip:
            return local_ip
    except Exception:
        pass
    finally:
        try:
            probe.close()
        except Exception:
            pass
    return "127.0.0.1"


def _decode_payload(text: str) -> bytes:
    return bytes(str(text or ""), "utf-8", errors="replace")


def _condition_satisfied(*, condition: str, state_name: str, event_name: str) -> bool:
    expr = str(condition or "").strip().lower()
    if not expr:
        return False
    expr = expr.replace('"', "").replace("'", "")
    if "state ==" in expr:
        expected = expr.split("state ==", 1)[1].strip()
        return bool(expected) and state_name == expected
    if "event ==" in expr:
        expected = expr.split("event ==", 1)[1].strip()
        return bool(expected) and event_name == expected
    return state_name in expr or event_name in expr


@dataclass
class _PendingExpect:
    condition: str
    timeout_at_s: float


@dataclass
class _FlowCtx:
    vu_id: int
    flow_name: str
    on_failure: str
    events: list[dict[str, Any]]
    idx: int = 0
    flow_id: int = 0
    pending: _PendingExpect | None = None
    closed: bool = False
    done: bool = False
    last_state: str = "closed"
    last_event: str = ""


class L4SessionDriver:
    """Scenario-engine L4 TCP flow runner over custom_tcp_dataplane."""

    def __init__(
        self,
        *,
        state_engine: Any,
        tcp_dataplane: Any,
        target_ip: str,
        ramp_controller: Any | None = None,
        source_ip: str | None = None,
        rng_seed: int = 1337,
    ) -> None:
        self._state_engine = state_engine
        self._dataplane = tcp_dataplane
        self._ramp_controller = ramp_controller
        self._target_ip = _resolve_ipv4(target_ip)
        self._source_ip = _resolve_ipv4(source_ip) if source_ip else _guess_source_ipv4(self._target_ip)
        self._target_u32 = _ip_to_u32(self._target_ip)
        self._source_u32 = _ip_to_u32(self._source_ip)
        self._rng = random.Random(int(rng_seed))
        self._ctx_by_vu: dict[int, _FlowCtx] = {}
        self._vu_by_flow_id: dict[int, int] = {}

    @staticmethod
    def packed_events_for_session(session: dict[str, Any]) -> list[dict[str, Any]]:
        src = dict((session or {}).get("__soa") or {}) if "__soa" in (session or {}) else dict(session or {})
        s0 = max(0, int((session or {}).get("__start", 0) or 0)) if "__soa" in (session or {}) else 0
        s1 = max(s0, int((session or {}).get("__end", 0) or 0)) if "__soa" in (session or {}) else len(list((src or {}).get("event_kind", []) or []))
        kinds = list((src or {}).get("event_kind", []) or [])
        dports = list((src or {}).get("tcp_dst_port", []) or [])
        payloads = list((src or {}).get("tcp_payload", []) or [])
        conds = list((src or {}).get("tcp_expect_condition", []) or [])
        to_ms = list((src or {}).get("tcp_expect_timeout_ms", []) or [])
        think_min = list((src or {}).get("think_min_ms", []) or [])
        think_max = list((src or {}).get("think_max_ms", []) or [])
        out: list[dict[str, Any]] = []
        for i in range(s0, min(s1, len(kinds))):
            k = int(kinds[i] or 0)
            if k == 1:
                out.append(
                    {
                        "type": "pause",
                        "think_time": {
                            "min_ms": int(think_min[i] if i < len(think_min) else 0),
                            "max_ms": int(think_max[i] if i < len(think_max) else 0),
                        },
                    }
                )
            elif k == 2:
                out.append({"type": "tcp_connect", "dst_port": int(dports[i] if i < len(dports) else 0)})
            elif k == 3:
                out.append({"type": "tcp_send", "payload_template": str(payloads[i] if i < len(payloads) else "")})
            elif k == 4:
                out.append(
                    {
                        "type": "tcp_expect",
                        "condition": str(conds[i] if i < len(conds) else ""),
                        "timeout_ms": int(to_ms[i] if i < len(to_ms) else 0),
                    }
                )
            elif k == 5:
                out.append({"type": "tcp_close"})
        return out

    def spawn_flow(self, vu_id: int, events: list[dict[str, Any]], *, flow_name: str = "unknown", on_failure: str = "retry") -> int:
        ctx = _FlowCtx(
            vu_id=int(vu_id),
            flow_name=str(flow_name or "unknown"),
            on_failure=str(on_failure or "retry").strip().lower() or "retry",
            events=list(events or []),
        )
        self._ctx_by_vu[ctx.vu_id] = ctx
        self._advance_ctx(ctx, now_s=0.0)
        return int(ctx.flow_id or 0)

    def tick(self, elapsed_s: float) -> list[dict[str, Any]]:
        now_s = max(0.0, float(elapsed_s))
        now_ns = int(time.monotonic_ns())
        try:
            self._dataplane.poll_tcp_dataplane(now_ns, 4096)
        except Exception:
            pass
        rows: list[dict[str, Any]] = []
        completions = list(self._dataplane.collect_tcp_completions() or [])
        for item in completions:
            flow_id = int((item or {}).get("flow_id", 0) or 0)
            vu_id = self._vu_by_flow_id.get(flow_id)
            if vu_id is None:
                continue
            ctx = self._ctx_by_vu.get(vu_id)
            if ctx is None:
                continue
            state_raw = int((item or {}).get("state", 0) or 0)
            ctx.last_state = _TCP_STATE_MAP.get(state_raw, "closed")
            ctx.last_event = str((item or {}).get("event", "") or "").strip().lower()
            success = bool(int((item or {}).get("success", 0) or 0))
            if ctx.pending is not None and _condition_satisfied(
                condition=ctx.pending.condition, state_name=ctx.last_state, event_name=ctx.last_event
            ):
                rows.append(self._result_row(ctx=ctx, success=True, timeout=False, latency_ms=0.0))
                ctx.pending = None
                self._advance_ctx(ctx, now_s=now_s, rows=rows)
            elif not success and ctx.pending is not None:
                rows.append(self._result_row(ctx=ctx, success=False, timeout=False, latency_ms=0.0))
                ctx.pending = None
                ctx.done = True
        for ctx in list(self._ctx_by_vu.values()):
            if ctx.pending is not None and now_s >= ctx.pending.timeout_at_s:
                rows.append(self._result_row(ctx=ctx, success=False, timeout=True, latency_ms=0.0))
                ctx.pending = None
                ctx.done = True
        return rows

    def send_payload(self, vu_id: int, payload: bytes) -> None:
        ctx = self._ctx_by_vu.get(int(vu_id))
        if ctx is None or ctx.flow_id <= 0:
            return
        self._dataplane.enqueue_tcp_send(int(ctx.flow_id), bytes(payload or b""))

    def close_flow(self, vu_id: int) -> None:
        ctx = self._ctx_by_vu.get(int(vu_id))
        if ctx is None:
            return
        ctx.closed = True
        ctx.done = True

    def snapshot(self) -> dict[str, Any]:
        snap = dict(self._dataplane.snapshot_tcp_dataplane() or {})
        snap["scenario_l4_active_vus"] = int(sum(1 for c in self._ctx_by_vu.values() if not c.done))
        snap["scenario_l4_total_vus"] = int(len(self._ctx_by_vu))
        return snap

    def _result_row(self, *, ctx: _FlowCtx, success: bool, timeout: bool, latency_ms: float) -> dict[str, Any]:
        return {
            "flow": str(ctx.flow_name or "unknown"),
            "vu_id": str(ctx.vu_id),
            "on_failure": str(ctx.on_failure or "retry"),
            "success": bool(success),
            "timeout": bool(timeout),
            "latency_ms": float(latency_ms),
        }

    def _advance_ctx(self, ctx: _FlowCtx, *, now_s: float, rows: list[dict[str, Any]] | None = None) -> None:
        out_rows = rows if rows is not None else []
        while not ctx.done and ctx.pending is None and ctx.idx < len(ctx.events):
            step = dict(ctx.events[ctx.idx] or {})
            st = str(step.get("type", "") or "").strip().lower()
            ctx.idx += 1
            if st == "pause":
                continue
            if st == "tcp_connect":
                dst_port = max(1, min(65535, int(step.get("dst_port", 0) or 0)))
                src_port = int(self._rng.randint(32768, 60999))
                flow_id = int(self._dataplane.enqueue_tcp_connect(self._source_u32, self._target_u32, src_port, dst_port) or 0)
                if flow_id <= 0:
                    out_rows.append(self._result_row(ctx=ctx, success=False, timeout=False, latency_ms=0.0))
                    ctx.done = True
                    return
                ctx.flow_id = flow_id
                self._vu_by_flow_id[flow_id] = ctx.vu_id
                continue
            if st == "tcp_send":
                payload = _decode_payload(str(step.get("payload_template", "") or ""))
                self.send_payload(ctx.vu_id, payload)
                out_rows.append(self._result_row(ctx=ctx, success=True, timeout=False, latency_ms=0.0))
                continue
            if st == "tcp_expect":
                timeout_ms = max(1, int(step.get("timeout_ms", 1000) or 1000))
                cond = str(step.get("condition", "") or "").strip()
                if _condition_satisfied(condition=cond, state_name=ctx.last_state, event_name=ctx.last_event):
                    out_rows.append(self._result_row(ctx=ctx, success=True, timeout=False, latency_ms=0.0))
                    continue
                ctx.pending = _PendingExpect(condition=cond, timeout_at_s=now_s + (float(timeout_ms) / 1000.0))
                return
            if st == "tcp_close":
                self.close_flow(ctx.vu_id)
                out_rows.append(self._result_row(ctx=ctx, success=True, timeout=False, latency_ms=0.0))
                return
        if ctx.idx >= len(ctx.events) and ctx.pending is None:
            ctx.done = True

