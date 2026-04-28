import logging
import os
import time
from typing import Dict, Any

log = logging.getLogger(__name__)


class LiveMetricsExporter:
    """Writes live attack metrics to a Prometheus textfile for node-exporter.

    This is intended to be used by the main process to periodically export
    aggregated worker stats.

    Exported gauges include sender_path breakdown, fallback counts, and
    permission errors for better runtime observability. Pacing V2 gauges
    (actual_rps, rate_accuracy, jitter_p99, txtime errors) are exported when
    provided by the orchestrator resource snapshots.
    """

    def __init__(
        self,
        prom_file: str = "monitoring/textfile/samurai.prom",
        prefix: str = "samurai_attack",
    ):
        self.prom_file = prom_file
        self.prefix = prefix
        self._last_stats: Dict[str, Any] = {}
        self._last_time = time.time()
        self._write_errors = 0  # track consecutive write failures
        self._write_error_total = 0

        # Ensure directory exists
        try:
            os.makedirs(os.path.dirname(self.prom_file), exist_ok=True)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as e:
            log.warning("LiveMetricsExporter: cannot create prom dir %s: %s", self.prom_file, e)

    def export(self, stats: Dict[str, Any]) -> None:
        """Export live stats to Prometheus textfile.

        Stats should contain:
        - sent_total
        - attempted_total
        - errors_total
        - workers_active
        - progress_pct
        - pps (optional, can be calculated)
        - sender_paths_used (optional, dict of path->count)
        - fallback_count (optional)
        - permission_error_count (optional)
        """
        now = time.time()
        dt = now - self._last_time

        # Calculate PPS if not provided
        if "pps" not in stats and dt > 0:
            last_sent = self._last_stats.get("sent_total", 0)
            current_sent = stats.get("sent_total", 0)
            stats["pps"] = (current_sent - last_sent) / dt

        lines = []

        # Standard numeric gauges
        for k, v in stats.items():
            if k == "sender_paths_used":
                continue  # handled separately below
            name = self._sanitize_metric_name(f"{self.prefix}_{k}")
            if isinstance(v, (int, float)):
                mtype = self._metric_type_for_name(name)
                lines.append(f"# HELP {name} Live exporter metric for {k}.")
                lines.append(f"# TYPE {name} {mtype}")
                lines.append(f"{name} {v}")
            elif k == "run_quality" and isinstance(v, str):
                safe_quality = str(v).replace('"', '\\"')
                name = self._sanitize_metric_name(f"{self.prefix}_run_quality")
                lines.append(f"# HELP {name} Current run quality status.")
                lines.append(f"# TYPE {name} gauge")
                lines.append(f'{self.prefix}_run_quality{{quality="{safe_quality}"}} 1')
            elif k == "kpi_gate_status" and isinstance(v, str):
                safe_status = str(v).replace('"', '\\"')
                name = self._sanitize_metric_name(f"{self.prefix}_kpi_gate_status")
                lines.append(f"# HELP {name} Current KPI gate status.")
                lines.append(f"# TYPE {name} gauge")
                lines.append(f'{self.prefix}_kpi_gate_status{{status="{safe_status}"}} 1')

        # Sender path breakdown (labelled gauge)
        sender_paths = stats.get("sender_paths_used")
        if isinstance(sender_paths, dict):
            path_name = self._sanitize_metric_name(f"{self.prefix}_sender_path")
            lines.append(f"# HELP {path_name} Sender backend path counters.")
            lines.append(f"# TYPE {path_name} gauge")
            for sender_path_name, path_count in sender_paths.items():
                safe_name = str(sender_path_name).replace('"', '\\"')
                lines.append(
                    f"{path_name}" + f'{{path="{safe_name}"}} {int(path_count)}'
                )

        export_ts_name = self._sanitize_metric_name(f"{self.prefix}_export_timestamp_seconds")
        lines.append(f"# HELP {export_ts_name} Last successful metrics export attempt timestamp.")
        lines.append(f"# TYPE {export_ts_name} gauge")
        lines.append(f"{export_ts_name} {now}")
        write_err_name = self._sanitize_metric_name(f"{self.prefix}_write_error_total")
        lines.append(f"# HELP {write_err_name} Total number of exporter write errors.")
        lines.append(f"# TYPE {write_err_name} counter")
        lines.append(f"{write_err_name} {int(self._write_error_total)}")

        # Atomic write with visible error reporting
        tmp_file = self.prom_file + ".tmp"
        try:
            with open(tmp_file, "w") as f:
                f.write("\n".join(lines) + "\n")
            os.replace(tmp_file, self.prom_file)
            # Reset error counter on success
            if self._write_errors > 0:
                log.info(
                    "LiveMetricsExporter: recovered after %d write errors, "
                    "file=%s",
                    self._write_errors,
                    self.prom_file,
                )
                self._write_errors = 0
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError) as e:
            self._write_errors += 1
            self._write_error_total += 1
            # Log only first failure and then every 10th to avoid spam
            if self._write_errors == 1 or self._write_errors % 10 == 0:
                log.warning(
                    "LiveMetricsExporter: write failed (count=%d): %s -> %s",
                    self._write_errors,
                    self.prom_file,
                    e,
                )

        self._last_stats = stats.copy()
        self._last_time = now

    @staticmethod
    def _sanitize_metric_name(name: str) -> str:
        out = []
        for ch in str(name):
            if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9") or ch in ("_", ":"):
                out.append(ch)
            else:
                out.append("_")
        metric = "".join(out)
        if not metric:
            return "samurai_attack_unknown"
        if not (metric[0].isalpha() or metric[0] in ("_", ":")):
            return f"m_{metric}"
        return metric

    @staticmethod
    def _metric_type_for_name(metric_name: str) -> str:
        if metric_name.endswith("_total") or metric_name.endswith("_count"):
            return "counter"
        return "gauge"
