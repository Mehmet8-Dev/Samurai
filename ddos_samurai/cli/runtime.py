"""Live runtime path for the CLI."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import multiprocessing
import os
import time
from datetime import datetime, timezone

from .. import metrics, reporting, stealth, utils
from ..profile_names import PROFILE_NONE
from .helpers import _is_cuda_raw_vector, is_admin, print_distributed_info
from .offline_modes import export_jsonl_rows, generate_traffic_plan
from .profile_resolver import apply_profile, _resolve_profile_args
from .reporting import (
    aggregate_worker_events,
    build_loss_summary,
    publish_metrics_prom_to_textfile,
    report_inputs_from_args,
)
from .validation import _resolve_worker_queue_map

_CPU_RAW_SOCKET_VECTORS = {
    "basic", "dns", "anomaly",
    "ntp-amp", "ssdp-amp", "dns-amp", "memcached-amp", "ldap-amp",
    "pcap-replay",
}


def _load_payloads(args) -> list:
    payloads = []
    if args.payload_file:
        try:
            with open(args.payload_file, "rb") as f:
                payload_chunk = f.read()
                if payload_chunk:
                    payloads = [payload_chunk]
            if not payloads:
                utils.log_warning(f"Payload dosyası ({args.payload_file}) boş.")
            else:
                utils.log_info(f"{len(payloads[0])} bayt boyutunda payload dosyadan okundu.")
        except FileNotFoundError:
            utils.log_critical(f"Payload dosyası bulunamadı: {args.payload_file}")
            raise SystemExit(1)
        except Exception as e:
            utils.log_critical(f"Payload dosyası okunurken hata: {e}")
            raise SystemExit(1)
    elif args.payload:
        payloads = [args.payload]
    return payloads


def _prepare_ninja_mode(args) -> None:
    if not args.ninja_mode:
        args.cookies = None
        args.user_agent = None
        return

    utils.log_info("Ninja Mode: WAF Bypass başlatılıyor...")
    target_scheme = args.http_scheme if hasattr(args, "http_scheme") else "http"
    target_path = args.http_path[0] if hasattr(args, "http_path") and args.http_path else "/"
    target_url = f"{target_scheme}://{args.target}:{args.port}{target_path}"
    try:
        bypass_result = asyncio.run(stealth.WAFBypass(target_url, headless=True).bypass())
        if bypass_result:
            args.cookies = bypass_result["cookies"]
            args.user_agent = bypass_result["user_agent"]
            utils.log_info("Ninja Mode: Bypass başarılı. Cookies ve User-Agent worker'lara dağıtılıyor.")
            return
        utils.log_critical("Ninja Mode: WAF Bypass başarısız oldu. Saldırı iptal ediliyor.")
        raise SystemExit(1)
    except Exception as e:
        utils.log_critical(f"Ninja Mode Hatası: {e}")
        raise SystemExit(1)


def _validate_live_args(args, parser) -> None:
    if args.target is None or args.port is None:
        parser.error("Hata: 'target' ve 'port' argümanları ya komut satırında ya da konfigürasyon dosyasında belirtilmelidir.")
    if args.attack_vector == "anomaly" and args.compute_backend != "cuda":
        parser.error("Hata: 'anomaly' attack-vector yalnızca --compute-backend cuda ile desteklenir.")
    if args.attack_vector == "pcap-replay":
        pcap_file = getattr(args, "pcap_file", "") or ""
        if not pcap_file or not os.path.isfile(pcap_file):
            parser.error("Hata: 'pcap-replay' attack-vector için geçerli bir --pcap-file gereklidir.")


def run_live_mode(args, parser, argv, soak_cfg, report_ctx: dict, runtime_ctx: dict) -> int:
    _validate_live_args(args, parser)

    # ── License Feature Gates ───────────────────────────────────────────
    license_result = getattr(args, "_license_result", None)
    if license_result is not None:
        from ..licensing.gates import enforce_feature_gates, LicenseGateError
        try:
            gate_warnings = enforce_feature_gates(args, license_result)
            for warn in gate_warnings:
                utils.log_warning(f"Lisans: {warn}")
        except LicenseGateError as exc:
            utils.log_critical(f"Lisans kısıtlaması: {exc.message}")
            if exc.upgrade_hint:
                utils.log_info(f"  → {exc.upgrade_hint}")
            return 78  # EX_CONFIG
    # ── License Feature Gates End ───────────────────────────────────────

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        filename=args.log,
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] [%(processName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info("Ana süreç başlatıldı.")

    needs_root = (
        (args.attack_vector in _CPU_RAW_SOCKET_VECTORS)
        or _is_cuda_raw_vector(args)
        or bool(getattr(args, "use_so_txtime", False))
    )
    if needs_root and not is_admin():
        utils.log_critical("Hata: Bu saldırı vektörü raw socket gerektirdiği için ROOT (sudo) yetkisi gereklidir.")
        utils.log_info(f"Vektör: {args.attack_vector} (backend={args.compute_backend}, so_txtime={int(bool(args.use_so_txtime))})")
        utils.log_info("Lütfen aracı 'sudo' ile çalıştırın veya 'CAP_NET_RAW' yetkisini verin.")
        return 1

    from .. import orchestrator

    args.payloads = _load_payloads(args)

    apply_profile(args)
    _resolve_profile_args(parser, args, argv)
    print_distributed_info(args.role)
    utils.print_system_status(args)
    utils.log_info("Saldırı başlatılıyor...")

    tls_profile = args.tls_profile if hasattr(args, "tls_profile") else PROFILE_NONE
    h2_profile = args.h2_profile if hasattr(args, "h2_profile") else PROFILE_NONE
    args.ja3_profile = tls_profile
    args.tls_profile = tls_profile
    args.h2_profile = h2_profile

    if bool(getattr(args, "stealth_mode", False)):
        utils.log_warning("DEPRECATION: --stealth-mode davranissiz (no-op) ve kaldirilacak.")
    if getattr(args, "evasion_techniques", None):
        utils.log_warning("DEPRECATION: --evasion-techniques davranissiz (no-op) ve kaldirilacak.")

    _prepare_ninja_mode(args)

    if not args.confirm:
        utils.ethical_warning()
    ok, msg = utils.validate_target_safety(
        target_ip=args.target,
        allow_targets=args.allow_target,
        allow_public=args.allow_public_target,
    )
    if not ok:
        utils.log_critical(msg)
        return 2

    progress = multiprocessing.Value("L", 0)
    sent_total_shared = multiprocessing.Value("L", 0)
    errors_total_shared = multiprocessing.Value("L", 0)
    progress_lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    run_events = manager.list()
    resource_stats = manager.dict()

    workers = args.workers if args.workers > 0 else multiprocessing.cpu_count()
    try:
        worker_queue_map = _resolve_worker_queue_map(
            workers=int(workers),
            strategy=str(getattr(args, "dp_queue_strategy", "rr") or "rr"),
            dp_queues=int(getattr(args, "dp_queues", 1) or 1),
            map_spec=str(getattr(args, "dp_queue_map", "") or ""),
        )
    except Exception as exc:
        utils.log_critical(f"Dataplane queue map çözümleme hatası: {exc}")
        return 1

    soak_duration_s = int((soak_cfg or {}).get("duration_s", 0) or 0)
    if soak_cfg is not None and soak_duration_s > 0:
        soak_chunk_total = int(args.count or 0)
        if float(args.rps or 0.0) > 0.0:
            soak_chunk_total = max(soak_chunk_total, int(float(args.rps) * 5.0))
        soak_chunk_total = max(soak_chunk_total, workers * 64, 1024)
        soak_chunk_total = min(soak_chunk_total, 500000)
        total_count = int(soak_chunk_total)
        monitor_total_count = 0
        utils.log_info(
            f"Soak sürekli modu aktif: {soak_duration_s}s boyunca count toplam limiti uygulanmayacak "
            f"(iterasyon başına toplam batch: {total_count})."
        )
    else:
        total_count = int(args.count or 0)
        if total_count < workers:
            workers = total_count
            utils.log_warning(
                f"Toplam paket sayısı ({total_count}), işçi sayısından ({args.workers}) az. İşçi sayısı {total_count} olarak ayarlandı."
            )
        monitor_total_count = total_count

    count_per_worker = total_count // workers if workers > 0 else 0
    worker_counts = [count_per_worker] * workers
    remainder = total_count % workers if workers > 0 else 0
    for i in range(remainder):
        worker_counts[i] += 1

    traffic_model_sessions_by_worker = [[] for _ in range(workers)]
    if str(getattr(args, "traffic_model", "none") or "none").strip().lower() == "mamba2":
        try:
            plan = generate_traffic_plan(args, max(1, int(total_count or 1)), runtime_ctx)
            session_dicts = [
                sp.to_dict() if hasattr(sp, "to_dict") else dict(sp)
                for sp in list(getattr(plan, "session_plans", []) or [])
            ] if plan is not None else []
            cursor = 0
            for wi in range(workers):
                wc = int(worker_counts[wi] or 0)
                traffic_model_sessions_by_worker[wi] = list(session_dicts[cursor: cursor + wc])
                cursor += wc
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
                utils.log_info(f"Traffic model event export: {out}")
        except Exception as exc:
            utils.log_critical(f"Traffic model planner failed: {exc}")
            return 1

    utils.log_info(f"{workers} adet işçi (worker) süreci başlatılıyor...")

    processes = []
    start_time = time.time()
    soak_deadline_ts = (start_time + float(soak_duration_s)) if (soak_cfg is not None and soak_duration_s > 0) else 0.0
    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    interrupted = False
    monitor_summary = {}
    kpi_hard_fail_triggered = False

    for i in range(workers):
        if worker_counts[i] == 0:
            continue
        worker_args = argparse.Namespace(**vars(args))
        worker_args.count = worker_counts[i]
        worker_id = i + 1
        worker_queue_id = int(worker_queue_map.get(worker_id, getattr(args, "xdp_queue_id", 0)) or 0)
        worker_args.dp_queue_id = worker_queue_id
        worker_args.xdp_queue_id = worker_queue_id
        worker_args.dp_worker_queue_map = json.dumps(worker_queue_map, sort_keys=True)
        worker_args.traffic_model = str(getattr(args, "traffic_model", "none") or "none")
        worker_args.traffic_model_sessions = list(traffic_model_sessions_by_worker[i] or [])
        if soak_deadline_ts > 0.0:
            worker_args.soak_deadline_ts = float(soak_deadline_ts)
        if worker_args.rps > 0:
            worker_args.rps = worker_args.rps / workers

        p = multiprocessing.Process(
            target=orchestrator.start_worker,
            args=(
                i + 1,
                vars(worker_args),
                progress,
                progress_lock,
                tls_profile,
                run_events,
                sent_total_shared,
                errors_total_shared,
                resource_stats,
            ),
            name=f"Worker-{i+1}",
        )
        processes.append(p)
        p.start()

    try:
        monitor_summary = utils.attack_live_monitor(
            processes,
            progress,
            progress_lock,
            monitor_total_count,
            refresh=0.25,
            sent_total=sent_total_shared,
            errors_total=errors_total_shared,
            resource_stats=resource_stats,
            soak_config=soak_cfg,
        )
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        utils.log_critical("CTRL+C algılandı! Tüm süreçler sonlandırılıyor...")
        interrupted = True
    finally:
        for p in processes:
            if p.is_alive():
                p.terminate()
            p.join()
        utils.log_info("Tüm süreçler sonlandırıldı.")

    duration = time.time() - start_time
    utils.log_info(f"Tüm işçiler görevlerini tamamladı. Toplam süre: {duration:.2f} saniye.")
    if soak_cfg is not None:
        soak_passed = bool((monitor_summary or {}).get("passed", False))
        alarms_count = int(len((monitor_summary or {}).get("alarms", [])))
        status_txt = "PASS" if soak_passed else "FAIL"
        utils.log_info(
            f"Soak değerlendirme [{soak_cfg.get('profile','custom')}]: {status_txt} "
            f"(alarms={alarms_count}, snapshots={int((monitor_summary or {}).get('snapshot_count', 0))})."
        )

    if report_ctx["want_report"]:
        try:
            finished_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with progress_lock:
                progress_total = int(progress.value)

            events_local = list(run_events)
            agg = aggregate_worker_events(events_local)
            m = metrics.global_metrics()
            try:
                m.set_gauge("live_workers_total", float(agg.get("workers_total", 0)))
                m.set_gauge("live_workers_ok", float(agg.get("workers_ok", 0)))
                m.set_gauge("live_workers_failed", float(agg.get("workers_failed", 0)))
                m.set_gauge("live_workers_interrupted", float(agg.get("workers_interrupted", 0)))
                m.set_gauge("live_attempted_total", float(agg.get("attempted_total", 0)))
                m.set_gauge("live_sent_total", float(agg.get("sent_total", 0)))
                m.set_gauge("live_errors_total", float(agg.get("errors_total", 0)))
                m.set_gauge("live_progress_total", float(progress_total))
                m.observe("live_wall_s", float(duration))
                if duration > 0:
                    m.set_gauge("live_effective_pps", float(agg.get("sent_total", 0)) / float(duration))
                if soak_cfg is not None:
                    m.set_gauge("soak_enabled", 1.0)
                    m.set_gauge("soak_passed", 1.0 if bool((monitor_summary or {}).get("passed", False)) else 0.0)
                    m.set_gauge("soak_alarms_total", float(len((monitor_summary or {}).get("alarms", []))))
                    m.set_gauge("soak_snapshots_total", float((monitor_summary or {}).get("snapshot_count", 0) or 0))
            except Exception:
                pass

            warnings = []
            if interrupted:
                warnings.append("run_interrupted_by_user")
            if int(agg.get("workers_failed", 0)) > 0:
                warnings.append("one_or_more_workers_failed")
            if soak_cfg is not None and not bool((monitor_summary or {}).get("passed", False)):
                warnings.append("soak_pass_fail_violation")
            for alarm in list((monitor_summary or {}).get("alarms", []) or []):
                code = str(alarm.get("code", "")).strip()
                if code:
                    warnings.append(f"soak_alarm:{code}")

            rr = reporting.build_live_attack_report(
                args=report_inputs_from_args(args),
                worker_events=events_local,
                duration_s=float(duration),
                progress_total=int(progress_total),
                total_count=int(progress_total if soak_cfg is not None else total_count),
                metrics=m.snapshot(),
                warnings=warnings,
            )
            rr.started_utc = started_utc
            rr.finished_utc = finished_utc
            rr.results["traffic_model"] = str(runtime_ctx.get("mode", "none") or "none")
            rr.results["traffic_model_name"] = str(runtime_ctx.get("model_name", "none") or "none")
            rr.results["traffic_model_checkpoint"] = str(runtime_ctx.get("checkpoint_id", "") or "")
            rr.results["traffic_model_plan_id"] = str(runtime_ctx.get("plan_id", "") or "")
            rr.results["traffic_model_seed"] = int(runtime_ctx.get("seed", 0) or 0)
            rr.results["traffic_model_session_count"] = int(runtime_ctx.get("session_count", 0) or 0)
            rr.results["traffic_model_event_count"] = int(runtime_ctx.get("event_count", 0) or 0)
            rr.results["traffic_model_fallback_used"] = int(bool(runtime_ctx.get("fallback_used", False)))
            rr.results["traffic_model_fallback_reason"] = str(runtime_ctx.get("fallback_reason", "none") or "none")
            if soak_cfg is not None:
                rr.results["soak_profile"] = str(soak_cfg.get("profile", "custom"))
                rr.results["soak_passed"] = bool((monitor_summary or {}).get("passed", False))
                rr.results["soak_snapshot_count"] = int((monitor_summary or {}).get("snapshot_count", 0) or 0)
                rr.results["soak_alarms"] = list((monitor_summary or {}).get("alarms", []) or [])
                rr.results["soak_thresholds"] = dict((monitor_summary or {}).get("thresholds", {}) or {})
                rr.results["soak_baseline"] = dict((monitor_summary or {}).get("baseline", {}) or {})
            if int(rr.results.get("kpi_gate_hard_fail", 0) or 0) == 1:
                kpi_hard_fail_triggered = True
                utils.log_critical("KPI gate hard-fail tetiklendi: " + ", ".join([str(x) for x in list(rr.results.get("kpi_violations", []))]))

            base = report_ctx["report_base"] or f"live_{int(start_time)}"
            base_path = os.path.join(os.getcwd(), report_ctx["report_dir"], base)
            if soak_cfg is not None and (monitor_summary or {}).get("snapshots"):
                snapshots_out = reporting.write_text(
                    json.dumps((monitor_summary or {}).get("snapshots", []), indent=2, sort_keys=True),
                    base_path + ".soak.snapshots.json",
                )
                rr.artifacts.append(reporting.Artifact(kind="soak_snapshots_json", path=snapshots_out, meta={"snapshots": int((monitor_summary or {}).get("snapshot_count", 0) or 0)}))
            dataset_capture_out = str(getattr(args, "traffic_model_dataset_capture", "") or "").strip()
            if dataset_capture_out:
                rows = []
                for ev in events_local:
                    rows.append(
                        {
                            "timestamp_utc": finished_utc,
                            "worker_id": int(ev.get("worker_id", 0) or 0),
                            "attack_vector": str(ev.get("attack_vector", "")),
                            "status": str(ev.get("status", "")),
                            "error": str(ev.get("error", "")),
                            "stats": dict(ev.get("stats", {}) or {}),
                        }
                    )
                dataset_path = export_jsonl_rows(rows, dataset_capture_out)
                rr.artifacts.append(reporting.Artifact(kind="traffic_model_dataset_capture_jsonl", path=dataset_path, meta={"rows": int(len(rows))}))
            if report_ctx["report_fmt"] in ("json", "both"):
                reporting.write_json(rr, base_path + ".json")
            if report_ctx["report_fmt"] in ("md", "both"):
                reporting.write_markdown(rr, base_path + ".md")
            extra = reporting.write_metrics_files(rr, base_path)
            publish_metrics_prom_to_textfile(extra.get("metrics_prom", ""))
            if report_ctx["loss_report_out"]:
                loss_summary = build_loss_summary(rr.results, finished_utc)
                reporting.write_text(json.dumps(loss_summary, indent=2, sort_keys=True), report_ctx["loss_report_out"])
        except Exception as e:
            utils.log_warning(f"Run raporu üretilemedi: {e}")
    try:
        manager.shutdown()
    except Exception:
        pass
    if kpi_hard_fail_triggered:
        return 2
    return 0
