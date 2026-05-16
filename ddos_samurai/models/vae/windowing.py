from __future__ import annotations

from collections import deque

import numpy as np

from .config import VAEConfig


class SlidingWindowBuffer:
    """Collects 1s metric points and emits windows every step_size seconds."""

    def __init__(self, config: VAEConfig):
        self._cfg = config
        self._buf: deque[np.ndarray] = deque(maxlen=config.window_size)
        # Keep one full-step warm-up after the first complete window.
        # This preserves deterministic cadence expected by tests/runtime:
        # first emit occurs after `window_size + step_size` pushes.
        self._since_last_emit = -1

    def push(self, point: dict[str, float]) -> np.ndarray | None:
        arr = np.array([float(point.get(name, 0.0)) for name in self._cfg.feature_names], dtype=np.float32)
        self._buf.append(arr)

        if len(self._buf) < self._cfg.window_size:
            return None

        self._since_last_emit += 1
        if self._since_last_emit < self._cfg.step_size:
            return None

        self._since_last_emit = 0
        return np.stack(list(self._buf), axis=0)
