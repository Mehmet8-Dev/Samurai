from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import numpy as np

try:
    import cupy as cp
except Exception:  # pragma: no cover - optional GPU dependency
    cp = None


@dataclass(frozen=True)
class D2HTransferMetrics:
    copy_count: int
    copy_bytes: int
    pinned_reuse_count: int
    pinned_alloc_count: int


class D2HTransferEngine:
    """
    Pinned-memory backed D2H transfer helper for gpu_cuda_payload.
    Supports sync/async transfer tokens with explicit wait() lifecycle.
    """

    def __init__(self, max_pinned_mb: int = 256) -> None:
        self._max_pinned_bytes = max(1, int(max_pinned_mb)) * 1024 * 1024
        self._pool: Dict[str, Any] = {}
        self._copy_count = 0
        self._copy_bytes = 0
        self._pinned_reuse_count = 0
        self._pinned_alloc_count = 0

    def metrics(self) -> D2HTransferMetrics:
        return D2HTransferMetrics(
            copy_count=int(self._copy_count),
            copy_bytes=int(self._copy_bytes),
            pinned_reuse_count=int(self._pinned_reuse_count),
            pinned_alloc_count=int(self._pinned_alloc_count),
        )

    def _as_numpy(self, arr: Any) -> np.ndarray:
        if isinstance(arr, np.ndarray):
            return arr
        if cp is not None and isinstance(arr, cp.ndarray):
            return cp.asnumpy(arr)
        return np.asarray(arr)

    def _alloc_or_reuse_pinned(self, key: str, nbytes: int):
        if cp is None:
            return None
        if nbytes > self._max_pinned_bytes:
            raise ValueError(
                f"requested D2H pinned buffer exceeds max_pinned_mb ({nbytes} > {self._max_pinned_bytes})"
            )
        existing = self._pool.get(key)
        if existing is not None and int(getattr(existing, "nbytes", 0) or 0) >= nbytes:
            self._pinned_reuse_count += 1
            return existing
        buf = cp.cuda.alloc_pinned_memory(nbytes)
        self._pool[key] = buf
        self._pinned_alloc_count += 1
        return buf

    def copy_to_host_sync(self, gpu_arr: Any, key: str = "default", stream: Optional[Any] = None) -> memoryview:
        if cp is None or not isinstance(gpu_arr, cp.ndarray):
            arr = np.ascontiguousarray(self._as_numpy(gpu_arr))
            self._copy_count += 1
            self._copy_bytes += int(arr.nbytes)
            return memoryview(arr).cast("B")

        arr = gpu_arr
        pinned = self._alloc_or_reuse_pinned(key, int(arr.nbytes))
        host = np.frombuffer(pinned, dtype=arr.dtype, count=arr.size).reshape(arr.shape)
        use_stream = stream or cp.cuda.get_current_stream()
        arr.get(out=host, stream=use_stream)
        use_stream.synchronize()
        self._copy_count += 1
        self._copy_bytes += int(arr.nbytes)
        return memoryview(host).cast("B")

    def copy_to_host_async(self, gpu_arr: Any, key: str = "default", stream: Optional[Any] = None) -> Dict[str, Any]:
        if cp is None or not isinstance(gpu_arr, cp.ndarray):
            buf = self.copy_to_host_sync(gpu_arr, key=key, stream=stream)
            return {"buffer": buf, "event": None, "nbytes": len(buf)}

        arr = gpu_arr
        pinned = self._alloc_or_reuse_pinned(key, int(arr.nbytes))
        host = np.frombuffer(pinned, dtype=arr.dtype, count=arr.size).reshape(arr.shape)
        use_stream = stream or cp.cuda.get_current_stream()
        arr.get(out=host, stream=use_stream)
        ev = cp.cuda.Event()
        ev.record(use_stream)
        self._copy_count += 1
        self._copy_bytes += int(arr.nbytes)
        return {"buffer": memoryview(host).cast("B"), "event": ev, "nbytes": int(arr.nbytes)}

    def wait_async(self, token: Dict[str, Any]) -> memoryview:
        ev = token.get("event")
        if ev is not None:
            ev.synchronize()
        buf = token.get("buffer")
        if not isinstance(buf, memoryview):
            raise TypeError("invalid async token: missing memoryview buffer")
        return buf
