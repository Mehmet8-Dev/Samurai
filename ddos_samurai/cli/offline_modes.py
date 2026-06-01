"""Offline CLI execution modes."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

from .. import metrics, reporting, selftest, utils
from .reporting import publish_metrics_prom_to_textfile


def export_jsonl_rows(rows, out_path: str) -> str:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for row in list(rows or []):
            f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
    return out_path


def generate_traffic_plan(args, total_sessions: int, runtime_ctx: dict):
    mode = str(getattr(args, "traffic_model", "none") or "none").strip().lower()
    if mode == "none":
        return None
    raise RuntimeError(
        "Legacy ddos_samurai.ml traffic model stack was removed. "
        "Use training/mamba2_monolith.py for train/eval/infer workflows."
    )


def handle_self_test(args, report_ctx: dict) -> int:
    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.time()
    m = metrics.global_metrics()

    summary = selftest.run_unittest_discover(
        start_dir="tests",
        pattern="test_*.py",
        top_level_dir=None,
        verbosity=2 if bool(args.verbose) else 1,
    )

    finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    duration_wall = max(0.0, time.time() - t0)
    try:
        m.set_gauge("self_test_tests_run", float(summary.get("tests_run", 0) or 0))
        m.set_gauge("self_test_failures", float(summary.get("failures", 0) or 0))
        m.set_gauge("self_test_errors", float(summary.get("errors", 0) or 0))
        m.set_gauge("self_test_skipped", float(summary.get("skipped", 0) or 0))
        m.observe("self_test_wall_s", float(duration_wall))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass

    if report_ctx["want_report"]:
        base = report_ctx["report_base"] or "self_test"
        base_path = os.path.join(os.getcwd(), report_ctx["report_dir"], base)
        log_path = reporting.write_text(summary.get("output", ""), base_path + ".log.txt")
        rr = reporting.build_self_test_report(
            summary=summary,
            log_path=log_path,
            duration_s=duration_wall,
            metrics=m.snapshot(),
            warnings=[],
        )
        rr.started_utc = started_utc
        rr.finished_utc = finished_utc
        if report_ctx["report_fmt"] in ("json", "both"):
            reporting.write_json(rr, base_path + ".json")
        if report_ctx["report_fmt"] in ("md", "both"):
            reporting.write_markdown(rr, base_path + ".md")
        extra = reporting.write_metrics_files(rr, base_path)
        publish_metrics_prom_to_textfile(extra.get("metrics_prom", ""))

    if not bool(summary.get("successful", False)):
        utils.log_critical("Self-test basarisiz (fail/error var).")
        return 1
    utils.log_info("Self-test OK.")
    return 0


def handle_gpu_pcap(args, report_ctx: dict) -> int:
    from .. import gpu_pcap_gen

    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.time()
    m = metrics.global_metrics()

    dst_ip = args.gpu_pcap_dst_ip or args.target or "127.0.0.1"
    tcp_port = args.gpu_pcap_tcp_port or (args.port if args.port else 80)
    udp_port = args.gpu_pcap_udp_port or (args.port if args.port else 53)
    out_name = args.gpu_pcap_out or f"gpu_generated_{args.gpu_pcap_duration}s_{args.gpu_pcap_pps}pps.pcap"

    cfg = gpu_pcap_gen.PcapGenConfig(
        duration_s=int(args.gpu_pcap_duration),
        pps=int(args.gpu_pcap_pps),
        mode=str(args.gpu_pcap_mode),
        src_ip=str(args.gpu_pcap_src_ip),
        dst_ip=str(dst_ip),
        tcp_dport=int(tcp_port),
        udp_dport=int(udp_port),
        chunk_size=int(args.gpu_pcap_chunk),
        seed=int(args.gpu_pcap_seed),
        flow_count=int(args.gpu_pcap_flow_count),
        realistic=bool(args.gpu_pcap_realistic),
        udp_checksum=bool(args.gpu_pcap_udp_checksum),
        variable_size=bool(args.gpu_pcap_variable_size),
        mtu=int(args.gpu_pcap_mtu),
        size_profile=str(args.gpu_pcap_size_profile),
        output_filename=str(out_name),
    )
    out_path = gpu_pcap_gen.generate_pcap(cfg, project_dir=os.getcwd())
    utils.log_info(f"GPU PCAP kaydedildi: {out_path}")

    realism_report = None
    realism_path = None
    if bool(args.gpu_pcap_realism_report):
        baseline = str(args.gpu_pcap_realism_baseline).strip() or None
        report_name = str(args.gpu_pcap_realism_out).strip() or f"{os.path.splitext(out_name)[0]}.realism.json"
        realism_report, realism_path = gpu_pcap_gen.generate_realism_report(
            out_path,
            mode=str(args.gpu_pcap_mode),
            size_profile=str(args.gpu_pcap_size_profile),
            realistic=bool(args.gpu_pcap_realistic),
            baseline_pcap=baseline,
            sample_packets=int(args.gpu_pcap_realism_sample),
            output_filename=report_name,
            project_dir=os.getcwd(),
        )

    if report_ctx["want_report"]:
        finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
        duration_wall = max(0.0, time.time() - t0)
        rr = reporting.build_gpu_pcap_report(
            cfg=cfg,
            pcap_path=str(out_path),
            realism=realism_report,
            realism_path=str(realism_path) if realism_path else None,
            duration_s=duration_wall,
            metrics=m.snapshot(),
            warnings=[],
        )
        rr.started_utc = started_utc
        rr.finished_utc = finished_utc
        base = report_ctx["report_base"] or f"{os.path.splitext(out_name)[0]}.run"
        base_path = os.path.join(os.getcwd(), report_ctx["report_dir"], base)
        if report_ctx["report_fmt"] in ("json", "both"):
            reporting.write_json(rr, base_path + ".json")
        if report_ctx["report_fmt"] in ("md", "both"):
            reporting.write_markdown(rr, base_path + ".md")
        extra = reporting.write_metrics_files(rr, base_path)
        publish_metrics_prom_to_textfile(extra.get("metrics_prom", ""))
    return 0


def handle_pcap_info(args, parser) -> int:
    pcap_file = getattr(args, "pcap_file", "") or ""
    if not pcap_file:
        parser.error("Hata: --pcap-info için --pcap-file gereklidir.")
    from .. import pcap_replay as _pcap_mod

    summary = _pcap_mod.pcap_summary(pcap_file)
    utils.log_info("\n── PCAP Dosya Özeti ──")
    for k, v in summary.items():
        if isinstance(v, dict):
            utils.log_info(f"  {k}:")
            for sk, sv in v.items():
                utils.log_info(f"    {sk}: {sv}")
        else:
            utils.log_info(f"  {k}: {v}")
    return 0


def handle_dry_run(args, parser, report_ctx: dict) -> int:
    utils.log_warning("--- DRY RUN MODE ---")
    if args.target is None or args.port is None:
        parser.error("Hata: 'target' ve 'port' argümanları ya komut satırında ya da konfigürasyon dosyasında belirtilmelidir.")

    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    t0 = time.time()
    m = metrics.global_metrics()
    warnings = []

    payload_obj = None
    payload_source = "none"
    payload_len = 0
    if getattr(args, "payload_file", ""):
        try:
            with open(args.payload_file, "rb") as f:
                payload_obj = f.read() or None
            payload_source = "payload_file"
            payload_len = len(payload_obj or b"")
        except FileNotFoundError:
            utils.log_critical(f"Payload dosyası bulunamadı: {args.payload_file}")
            return 1
    elif getattr(args, "payload", ""):
        payload_obj = args.payload
        payload_source = "payload_arg"
        payload_len = len(str(payload_obj))



    # ── ZMQ-based dispatch ──
    from .. import orchestrator

    worker_args = dict(vars(args))
    worker_args["packets"] = 1
    worker_args["count"] = 1
    worker_args["zmq_ack_timeout_s"] = 2.0
    worker_args["zmq_heartbeat_timeout_s"] = 5.0
    worker_args["zmq_overall_timeout_s"] = 10.0
    if "compute_backend" not in worker_args or not worker_args["compute_backend"]:
        worker_args["compute_backend"] = "cpu"

    run_events = []
    utils.log_info("Dry-run: ZMQ daemonuna doğrulama işi gönderiliyor...")
    try:
        orchestrator.start_worker_zmq(
            worker_id=1,
            args=worker_args,
            run_events=run_events,
        )
    except Exception as e:
        warnings.append(f"zmq_worker_exception: {type(e).__name__}: {e}")
        utils.log_warning(f"Dry-run: ZMQ worker başlatılamadı veya hata oluştu: {e}")

    zmq_ok = False
    if run_events:
        event = run_events[-1]
        if event.get("status") == "ok":
            zmq_ok = True
            utils.log_info(f"ZMQ Daemon doğrulandı: {event.get('status')}. ZMQ Süresi: {event.get('duration_s', 0.0):.4f}s.")
        else:
            zmq_err = event.get("error", "Bilinmeyen hata")
            warnings.append(f"zmq_worker_failed: {zmq_err}")
            utils.log_warning(f"Dry-run: ZMQ daemon hatası bildirdi: {zmq_err}")
    else:
        warnings.append("zmq_worker_no_response: ZMQ daemon'ından yanıt alınamadı.")
        utils.log_warning("Dry-run: ZMQ daemon'ından yanıt alınamadı.")

    # ── ZMQ-based inspection (metadata generation) ──
    pkt_bytes = b""
    if zmq_ok and run_events:
        stats = run_events[-1].get("stats", {})
        bytes_sent = stats.get("bytes_sent", 0)
        if bytes_sent > 0:
            pkt_bytes = b"\x00" * bytes_sent
            utils.log_info(f"Örnek paket boyutu ZMQ daemonundan alındı: {len(pkt_bytes)} bayt.")
        else:
            warnings.append("sample_packet_unavailable: ZMQ returned 0 bytes_sent")
            utils.log_warning("Dry-run: örnek paket boyutu alınamadı (0 bytes).")
    else:
        warnings.append("sample_packet_unavailable: ZMQ daemon failed")
        utils.log_warning("Dry-run: örnek paket üretilemedi (ZMQ hatası).")
        if not report_ctx["want_report"]:
            raise RuntimeError("Dry-run: örnek paket üretilemedi (ZMQ hatası).")

    finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    duration_wall = max(0.0, time.time() - t0)
    try:
        m.set_gauge("dry_run_sample_packet_len", float(len(pkt_bytes)))
        m.set_gauge("dry_run_payload_len", float(payload_len))
        m.observe("dry_run_wall_s", float(duration_wall))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass

    if report_ctx["want_report"]:
        args_for_report = {
            "target": args.target,
            "port": int(args.port),
            "protocol": str(args.protocol),
            "attack_vector": str(args.attack_vector),
            "compute_backend": str(getattr(args, "compute_backend", "")),
            "spoof": bool(args.spoof),
            "spoof_mode": str(args.spoof_mode),
            "fragment": bool(args.fragment),
            "fragment_size": int(args.fragment_size),
            "pad": int(args.pad),
            "payload_source": payload_source,
            "payload_len": int(payload_len),
        }
        rr = reporting.build_dry_run_report(
            args=args_for_report,
            packet_len=len(pkt_bytes),
            packet_hex_prefix=pkt_bytes[:64].hex(),
            duration_s=duration_wall,
            metrics=m.snapshot(),
            warnings=warnings,
        )
        rr.started_utc = started_utc
        rr.finished_utc = finished_utc
        base = report_ctx["report_base"] or "dry_run"
        base_path = os.path.join(os.getcwd(), report_ctx["report_dir"], base)
        if report_ctx["report_fmt"] in ("json", "both"):
            reporting.write_json(rr, base_path + ".json")
        if report_ctx["report_fmt"] in ("md", "both"):
            reporting.write_markdown(rr, base_path + ".md")
        extra = reporting.write_metrics_files(rr, base_path)
        publish_metrics_prom_to_textfile(extra.get("metrics_prom", ""))
    return 0


def handle_traffic_model_dry_validate(args, parser, runtime_ctx: dict) -> int:
    if str(getattr(args, "traffic_model", "none") or "none").strip().lower() == "none":
        parser.error("--traffic-model-dry-validate için --traffic-model mamba2 gereklidir.")
    plan = generate_traffic_plan(args, max(1, int(getattr(args, "count", 1) or 1)), runtime_ctx)
    export_path = str(getattr(args, "traffic_model_export_events", "") or "").strip()
    if export_path and plan is not None:
        rows = []
        for sp in list(getattr(plan, "session_plans", []) or []):
            for ev in list(getattr(sp, "events", []) or []):
                rows.append(
                    {
                        "plan_id": str(getattr(plan, "plan_id", "")),
                        "session_id": str(getattr(sp, "session_id", "")),
                        "protocol": str(getattr(sp, "protocol", "")),
                        "label": str(getattr(sp, "label", "")),
                        "event": ev.to_dict() if hasattr(ev, "to_dict") else dict(ev),
                    }
                )
        out = export_jsonl_rows(rows, export_path)
        utils.log_info(f"Traffic model dry-validate event export: {out}")
    utils.log_info(
        "Traffic model dry-validate OK: "
        f"plan_id={runtime_ctx.get('plan_id')} "
        f"sessions={runtime_ctx.get('session_count')} "
        f"events={runtime_ctx.get('event_count')} "
        f"fallback={int(bool(runtime_ctx.get('fallback_used', False)))} "
        f"reason={runtime_ctx.get('fallback_reason', 'none')}"
    )
    return 0


def dispatch_offline_mode(args, parser, report_ctx: dict, runtime_ctx: dict) -> int | None:
    if bool(getattr(args, "self_test", False)):
        return handle_self_test(args, report_ctx)
    if getattr(args, "gpu_pcap", False):
        return handle_gpu_pcap(args, report_ctx)
    if getattr(args, "pcap_info", False):
        return handle_pcap_info(args, parser)
    if bool(getattr(args, "dry_run", False)):
        return handle_dry_run(args, parser, report_ctx)
    if bool(getattr(args, "traffic_model_dry_validate", False)):
        return handle_traffic_model_dry_validate(args, parser, runtime_ctx)
    return None
