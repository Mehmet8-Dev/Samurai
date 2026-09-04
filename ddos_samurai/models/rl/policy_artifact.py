"""The trained policy as a torch-free artifact — the exact thing C++ will serve.

A ``PolicyArtifact`` is a small MLP (weights as numpy), the state normalizer, and
the action de-normalization bounds. Its ``act`` is a pure-numpy forward that
mirrors, op-for-op, what ``rl_policy.cpp`` will do at serving time — so it doubles
as the reference oracle for the export round-trip and for off-policy evaluation.
No torch here: training produces this, everything downstream consumes it.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True)
class PolicyArtifact:
    # Dense layers as (W, b): W is (out, in) row-major, b is (out,). All hidden
    # layers use ReLU; the output layer is linear, per-dim clamped to [0, 1] and
    # de-normalized with [action_lo[k], action_hi[k]] (linear+clamp avoids sigmoid
    # saturation at the range extremes). The output width equals the action dim.
    layers: list[tuple[np.ndarray, np.ndarray]]
    norm_mean: np.ndarray
    norm_std: np.ndarray
    action_lo: np.ndarray            # (A,) per-dim lower bound
    action_hi: np.ndarray            # (A,) per-dim upper bound
    feature_names: tuple[str, ...] = ()
    action_names: tuple[str, ...] = ("rps",)  # ordered; [0] is the primary setpoint

    @property
    def input_dim(self) -> int:
        return int(self.layers[0][0].shape[1])

    @property
    def action_dim(self) -> int:
        return int(self.layers[-1][0].shape[0])

    @property
    def hidden_dims(self) -> tuple[int, ...]:
        return tuple(int(W.shape[0]) for W, _ in self.layers[:-1])

    def _forward_norm(self, states_norm: np.ndarray) -> np.ndarray:
        """Raw network output (action-normalized, pre-clamp) for normalized states."""
        x = states_norm.astype(np.float32)
        n = len(self.layers)
        for i, (W, b) in enumerate(self.layers):
            x = x @ W.T + b
            if i < n - 1:
                x = np.maximum(x, 0.0)  # ReLU
        return x

    def act_batch(self, states: np.ndarray) -> np.ndarray:
        """Map raw (un-normalized) state rows -> (N, A) de-normalized actions."""
        std = np.where(self.norm_std == 0.0, 1.0, self.norm_std)
        z = (states.astype(np.float32) - self.norm_mean) / std
        frac = np.clip(self._forward_norm(z), 0.0, 1.0)
        return self.action_lo + frac * (self.action_hi - self.action_lo)

    def act(self, state: np.ndarray) -> float:
        """The primary (rps) setpoint for one raw state."""
        return float(self.act_batch(state[None, :])[0, 0])

    def act_vector(self, state: np.ndarray) -> np.ndarray:
        """The full (A,) action vector for one raw state."""
        return self.act_batch(state[None, :])[0]
