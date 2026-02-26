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

        # Ensure directory exists
        try:
            os.makedirs(os.path.dirname(self.prom_file), exist_ok=True)
        except Exception as e:
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
            name = f"{self.prefix}_{k}"
            if isinstance(v, (int, float)):
                lines.append(f"{name} {v}")

        # Sender path breakdown (labelled gauge)
        sender_paths = stats.get("sender_paths_used")
        if isinstance(sender_paths, dict):
            for path_name, path_count in sender_paths.items():
                safe_name = str(path_name).replace('"', '\\"')
                lines.append(
                    f'{self.prefix}_sender_path{{path="{safe_name}"}} {int(path_count)}'
                )

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
        except Exception as e:
            self._write_errors += 1
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
