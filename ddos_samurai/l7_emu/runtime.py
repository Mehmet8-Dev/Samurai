from __future__ import annotations

from typing import Any, Dict

from .. import utils
from .types import L7EmuProfile, RunResult, RuntimeConfig

log_warning = utils.log_warning

try:
    from .. import _l7_emu_native as _native
except Exception:  # pragma: no cover
    _native = None


def _unavailable_stats(profile: L7EmuProfile) -> Dict[str, Any]:
    attempted = int(profile.flow_attempted)
    return {
        "attempted": attempted,
        "sent": 0,
        "errors": attempted,
        "sender_path": str(profile.sender_path),
        "sender_fallback_reason": "l7_emu_native_unavailable",
        "l7_engine_path_used": "L7_EMU_NATIVE",
        "l7_fallback_reason": "l7_emu_native_unavailable",
        "l7_flow_attempted": attempted,
        "l7_flow_completed": 0,
        "l7_conn_attempted": 0,
        "l7_conn_established": 0,
        "l7_conn_reused": 0,
        "l7_rx_bytes": 0,
        "l7_tx_bytes": 0,
        "l7_status_2xx": 0,
        "l7_status_3xx": 0,
        "l7_status_4xx": 0,
        "l7_status_5xx": 0,
        "l7_expectation_failures": attempted,
        "l7_scheduler_backpressure_count": 0,
    }


async def run_l7_profile(
    profile: L7EmuProfile,
    runtime_cfg: RuntimeConfig,
) -> RunResult:
    if _native is None:
        log_warning("L7 emulation native module unavailable; run will fail-visible.")
        return RunResult(stats=_unavailable_stats(profile))
    stats = _native.run_profile(profile.as_dict(), runtime_cfg.as_dict())
    return RunResult(stats=dict(stats or {}))
