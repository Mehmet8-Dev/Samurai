import os
from typing import Any, Dict

import numpy as np

_RECOVERABLE_ERRORS = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
    ImportError,
    KeyError,
    IndexError,
)


def _env_int(name: str, default: int) -> int:
    raw = str(os.environ.get(name, str(default)) or str(default)).strip()
    try:
        return int(raw)
    except _RECOVERABLE_ERRORS:
        return int(default)


def _defense_enabled() -> bool:
    raw = str(os.environ.get("SAMURAI_GPU_DEFENSE_MODE", "off") or "off").strip().lower()
    return raw == "on"


def _defense_strict() -> bool:
    raw = str(os.environ.get("SAMURAI_GPU_RDMA_STRICT", "0") or "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _build_packet_views(mv: memoryview, *, count: int, packet_size: int, packet_stride: int) -> list[memoryview]:
    out: list[memoryview] = []
    stride = int(packet_stride or 0)
    size = int(packet_size or 0)
    for i in range(max(0, int(count))):
        start = i * (stride if stride > 0 else size)
        end = start + size
        out.append(mv[start:end])
    return out


def classify_packets_if_enabled(
    packets_buffer: Any,
    *,
    count: int,
    packet_size: int,
    packet_stride: int = 0,
    sender_context: Dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _defense_enabled():
        return {
            "gpu_defense_mode": "off",
            "gpu_classifier_invoked": 0,
        }
    try:
        from .. import _gpu_packet_cuda_backend as cuda_backend
    except _RECOVERABLE_ERRORS as exc:
        out = {
            "gpu_defense_mode": "on",
            "gpu_classifier_invoked": 0,
            "gpu_classifier_status": "unavailable",
            "gpu_classifier_error": f"import_failed:{type(exc).__name__}",
        }
        out["gpu_classifier_hard_fail"] = 1 if _defense_strict() else 0
        return out

    ctx = sender_context if isinstance(sender_context, dict) else {}
    backend = ctx.get("gpu_defense_backend")
    if backend is None:
        try:
            backend = cuda_backend.DefenseCUDABackend()
            backend.init(
                runtime=str(os.environ.get("SAMURAI_GPU_CLASSIFIER_RUNTIME", "tensorrt") or "tensorrt"),
                engine_path=str(os.environ.get("SAMURAI_GPU_CLASSIFIER_ENGINE_PATH", "") or ""),
                rdma_mode=str(os.environ.get("SAMURAI_GPU_RDMA_MODE", "auto") or "auto"),
                rdma_strict=_defense_strict(),
                max_batch_size=max(1, _env_int("SAMURAI_GPU_BATCH_MAX", 1024)),
                flush_timeout_ms=max(0, _env_int("SAMURAI_GPU_BATCH_FLUSH_TIMEOUT_MS", 2)),
            )
            if isinstance(sender_context, dict):
                sender_context["gpu_defense_backend"] = backend
        except _RECOVERABLE_ERRORS as exc:
            out = {
                "gpu_defense_mode": "on",
                "gpu_classifier_invoked": 0,
                "gpu_classifier_status": "init_failed",
                "gpu_classifier_error": f"init_failed:{type(exc).__name__}",
            }
            out["gpu_classifier_hard_fail"] = 1 if _defense_strict() else 0
            return out

    mv = memoryview(packets_buffer)
    pkt_views = _build_packet_views(
        mv,
        count=int(count),
        packet_size=int(packet_size),
        packet_stride=int(packet_stride or 0),
    )
    batch_max = max(1, _env_int("SAMURAI_GPU_BATCH_MAX", 1024))
    total = len(pkt_views)
    labels_all: list[np.ndarray] = []
    conf_all: list[np.ndarray] = []
    reason_last = "none"
    try:
        for i in range(0, total, batch_max):
            batch = pkt_views[i : i + batch_max]
            labels, confs, reason = backend.classify_batch([bytes(v) for v in batch])
            labels_all.append(labels)
            conf_all.append(confs)
            reason_last = str(reason or reason_last)
        labels_np = np.concatenate(labels_all) if labels_all else np.empty((0,), dtype=np.int32)
        conf_np = np.concatenate(conf_all) if conf_all else np.empty((0,), dtype=np.float32)
        suspicious = int(np.sum(labels_np != 0)) if labels_np.size > 0 else 0
        out = {
            "gpu_defense_mode": "on",
            "gpu_classifier_invoked": 1,
            "gpu_classifier_status": "ok",
            "gpu_classifier_reason": reason_last,
            "gpu_classifier_total": int(labels_np.size),
            "gpu_classifier_suspicious": int(suspicious),
            "gpu_classifier_benign": int(max(0, int(labels_np.size) - suspicious)),
            "gpu_classifier_confidence_mean": float(np.mean(conf_np)) if conf_np.size > 0 else 0.0,
            "gpu_classifier_confidence_max": float(np.max(conf_np)) if conf_np.size > 0 else 0.0,
        }
        stats = backend.read_classifier_stats()
        if isinstance(stats, dict):
            for k, v in stats.items():
                key = str(k).strip()
                if not key:
                    continue
                out[f"gpu_classifier_{key}"] = v
        return out
    except _RECOVERABLE_ERRORS as exc:
        out = {
            "gpu_defense_mode": "on",
            "gpu_classifier_invoked": 1,
            "gpu_classifier_status": "classify_failed",
            "gpu_classifier_error": f"classify_failed:{type(exc).__name__}",
        }
        out["gpu_classifier_hard_fail"] = 1 if _defense_strict() else 0
        return out
