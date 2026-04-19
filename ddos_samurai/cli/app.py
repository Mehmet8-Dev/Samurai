"""Thin CLI orchestration entrypoint."""

from __future__ import annotations

import logging

from .. import utils
from ..workload_profiles import print_profiles
from .args import build_parser
from .config import build_soak_config, load_config_defaults
from .constants import CONNECTION_POOL
from .env import sync_runtime_env
from .helpers import _maybe_enable_uvloop
from .offline_modes import dispatch_offline_mode
from .profile_resolver import apply_profile, _resolve_profile_args
from .runtime import run_live_mode
from .validation import (
    _preflight_l7_capabilities,
    _preflight_lab_profile,
    _preflight_persistent_tx_backend,
    _validate_hybrid_cuda_args,
    _validate_pacing_args,
    _validate_sender_route_args,
)


def main(argv=None):
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    utils.print_banner()
    _maybe_enable_uvloop()
    parser = build_parser()

    temp_args, _ = parser.parse_known_args(argv)
    parser.set_defaults(**load_config_defaults(getattr(temp_args, "config", None)))
    args = parser.parse_args(argv)
    _resolve_profile_args(parser, args, argv)

    if getattr(args, "list_profiles", False):
        print_profiles()
        raise SystemExit(0)

    apply_profile(args)
    _resolve_profile_args(parser, args, argv)
    _validate_pacing_args(parser, args)
    _validate_hybrid_cuda_args(parser, args)
    _validate_sender_route_args(parser, args)
    _preflight_lab_profile(parser, args)
    _preflight_persistent_tx_backend(parser, args)
    _preflight_l7_capabilities(parser, args)

    traffic_model_mode = str(getattr(args, "traffic_model", "none") or "none").strip().lower()
    if traffic_model_mode == "mamba2":
        parser.error(
            "--traffic-model mamba2 runtime entegrasyonu geçici olarak devre dışı. "
            "Ayrı eğitim/çıkarım akışı için training/mamba2_monolith.py train|eval|infer-plan kullanın."
        )

    global CONNECTION_POOL
    try:
        CONNECTION_POOL = max(1, int(args.connection_pool))
    except Exception:
        pass

    want_report = bool(getattr(args, "run_report", False)) or bool(getattr(args, "gpu_pcap_run_report", False))
    report_fmt = str(getattr(args, "run_report_format", getattr(args, "gpu_pcap_run_report_format", "both")))
    report_dir = str(getattr(args, "run_report_dir", "reports/runs"))
    report_base = str(getattr(args, "run_report_out", "")).strip() or str(getattr(args, "gpu_pcap_run_report_out", "")).strip()
    if bool(getattr(args, "kpi_hard_fail", False)) or str(getattr(args, "kpi_gate_profile", "off") or "off") != "off":
        want_report = True

    soak_cfg = build_soak_config(args)
    env_ctx = sync_runtime_env(args)
    runtime_ctx = {
        "mode": str(getattr(args, "traffic_model", "none") or "none"),
        "model_name": "none",
        "checkpoint_id": "",
        "seed": int(getattr(args, "traffic_model_seed", 1337) or 1337),
        "plan_id": "",
        "session_count": 0,
        "event_count": 0,
        "fallback_used": False,
        "fallback_reason": "none",
        "validation_errors": [],
    }
    report_ctx = {
        "want_report": want_report,
        "report_fmt": report_fmt,
        "report_dir": report_dir,
        "report_base": report_base,
        "loss_report_out": env_ctx["loss_report_out"],
    }

    offline_result = dispatch_offline_mode(args, parser, report_ctx, runtime_ctx)
    if offline_result is not None:
        raise SystemExit(offline_result)
    raise SystemExit(run_live_mode(args, parser, argv, soak_cfg, report_ctx, runtime_ctx))
