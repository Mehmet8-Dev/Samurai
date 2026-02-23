from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


def _now_s() -> float:
    return time.perf_counter()


def _label_key(labels: Optional[Dict[str, Any]]) -> Tuple[Tuple[str, str], ...]:
    if not labels:
        return ()
    # Stable, JSON-friendly labels.
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


@dataclass
class _Agg:
    n: int = 0
    sum: float = 0.0
    min: Optional[float] = None
    max: Optional[float] = None

    def add(self, v: float) -> None:
        self.n += 1
        self.sum += float(v)
        self.min = float(v) if self.min is None else min(self.min, float(v))
        self.max = float(v) if self.max is None else max(self.max, float(v))

    def to_dict(self) -> Dict[str, Any]:
        avg = (self.sum / self.n) if self.n else None
        return {"n": self.n, "sum": self.sum, "min": self.min, "max": self.max, "avg": avg}


class Metrics:
    """Tiny in-process metrics store (counters, gauges, simple observations).

    Intended for offline/test reporting. It is not a full monitoring stack.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
        self._obs: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], _Agg] = {}

    def inc(self, name: str, value: float = 1.0, labels: Optional[Dict[str, Any]] = None) -> None:
        key = (str(name), _label_key(labels))
        with self._lock:
            self._counters[key] = float(self._counters.get(key, 0.0)) + float(value)

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, Any]] = None) -> None:
        key = (str(name), _label_key(labels))
        with self._lock:
            self._gauges[key] = float(value)

    def observe(self, name: str, value: float, labels: Optional[Dict[str, Any]] = None) -> None:
        key = (str(name), _label_key(labels))
        with self._lock:
            agg = self._obs.get(key)
            if agg is None:
                agg = _Agg()
                self._obs[key] = agg
            agg.add(float(value))

    @contextmanager
    def timer(self, name: str, labels: Optional[Dict[str, Any]] = None) -> Iterator[None]:
        t0 = _now_s()
        try:
            yield
        finally:
            dt = max(0.0, _now_s() - t0)
            self.observe(name, dt, labels=labels)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            counters = {
                self._format_key(k): v for k, v in sorted(self._counters.items(), key=lambda kv: kv[0])
            }
            gauges = {
                self._format_key(k): v for k, v in sorted(self._gauges.items(), key=lambda kv: kv[0])
            }
            obs = {
                self._format_key(k): agg.to_dict()
                for k, agg in sorted(self._obs.items(), key=lambda kv: kv[0])
            }
        return {"counters": counters, "gauges": gauges, "observations": obs}

    def _format_key(self, key: Tuple[str, Tuple[Tuple[str, str], ...]]) -> str:
        name, labels = key
        if not labels:
            return name
        lbl = ",".join(f"{k}={v}" for k, v in labels)
        return f"{name}{{{lbl}}}"

    def clear(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._obs.clear()


_GLOBAL = Metrics()


def global_metrics() -> Metrics:
    return _GLOBAL


def reset_global_metrics() -> None:
    _GLOBAL.clear()
