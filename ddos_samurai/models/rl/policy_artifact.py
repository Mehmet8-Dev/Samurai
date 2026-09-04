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
    # layers use ReLU; the output layer is linear. Its width equals the sum of the
    # per-dim head widths: a continuous dim consumes ONE output (clamped to [0,1]
    # then de-normalized with [action_lo[k], action_hi[k]]); a categorical dim
    # consumes len(categories[k]) outputs read as logits (argmax -> category value).
    # When action_kinds is empty every dim is continuous and the output width equals
    # the action dim (the legacy all-continuous contract).
    layers: list[tuple[np.ndarray, np.ndarray]]
    norm_mean: np.ndarray
    norm_std: np.ndarray
    action_lo: np.ndarray            # (A,) per-dim lower bound
    action_hi: np.ndarray            # (A,) per-dim upper bound
    feature_names: tuple[str, ...] = ()
    action_names: tuple[str, ...] = ("rps",)  # ordered; [0] is the primary setpoint
    action_kinds: tuple[str, ...] = ()        # per-dim "continuous"/"categorical"
    action_categories: tuple = ()             # per-dim tuple[float,...] or None

    @property
    def input_dim(self) -> int:
        return int(self.layers[0][0].shape[1])

    @property
    def output_width(self) -> int:
        """Width of the network's output layer (>= action_dim with categorical heads)."""
        return int(self.layers[-1][0].shape[0])

    @property
    def action_dim(self) -> int:
        """Number of action dimensions (not output width)."""
        if self.action_kinds:
            return len(self.action_kinds)
        return self.output_width

    @property
    def hidden_dims(self) -> tuple[int, ...]:
        return tuple(int(W.shape[0]) for W, _ in self.layers[:-1])

    def _kinds(self) -> tuple[str, ...]:
        return self.action_kinds or ("continuous",) * self.output_width

    def _forward_norm(self, states_norm: np.ndarray) -> np.ndarray:
        """Raw network output (per-dim heads, pre-decode) for normalized states."""
        x = states_norm.astype(np.float32)
        n = len(self.layers)
        for i, (W, b) in enumerate(self.layers):
            x = x @ W.T + b
            if i < n - 1:
                x = np.maximum(x, 0.0)  # ReLU
        return x

    def act_batch(self, states: np.ndarray) -> np.ndarray:
        """Map raw (un-normalized) state rows -> (N, A) de-normalized actions.

        Walks the flat output positionally per dim: continuous -> clamp+denorm,
        categorical -> argmax over its logits mapped back to the category value.
        """
        std = np.where(self.norm_std == 0.0, 1.0, self.norm_std)
        z = (states.astype(np.float32) - self.norm_mean) / std
        out = self._forward_norm(z)

        kinds = self._kinds()
        if all(k == "continuous" for k in kinds) and not self.action_categories:
            frac = np.clip(out, 0.0, 1.0)
            return self.action_lo + frac * (self.action_hi - self.action_lo)

        n = out.shape[0]
        result = np.empty((n, len(kinds)), dtype=np.float32)
        col = 0
        for k, kind in enumerate(kinds):
            if kind == "categorical":
                cats = np.asarray(self.action_categories[k], dtype=np.float32)
                width = int(cats.size)
                idx = np.argmax(out[:, col:col + width], axis=1)
                result[:, k] = cats[idx]
                col += width
            else:
                frac = np.clip(out[:, col], 0.0, 1.0)
                result[:, k] = self.action_lo[k] + frac * (self.action_hi[k] - self.action_lo[k])
                col += 1
        return result

    def act(self, state: np.ndarray) -> float:
        """The primary (rps) setpoint for one raw state."""
        return float(self.act_batch(state[None, :])[0, 0])

    def act_vector(self, state: np.ndarray) -> np.ndarray:
        """The full (A,) action vector for one raw state."""
        return self.act_batch(state[None, :])[0]
