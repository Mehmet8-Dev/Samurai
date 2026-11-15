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


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


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

    # RL² in-context context encoder (the "Mahoraga wheel" made the network itself).
    # A single GRU cell run once per closed-loop window whose hidden state is carried
    # ACROSS the episode, so the SAME frozen weights produce different actions as the
    # trajectory accumulates — no weight update needed. None on a feedforward policy.
    # Packed exactly like torch.nn.GRUCell (gate order reset, update, new):
    #   gru_w_ih (3H, T)  gru_w_hh (3H, H)  gru_b_ih (3H,)  gru_b_hh (3H,)
    # where H = hidden size and T = token width = state_feat_dim + action_dim. The
    # per-window token is [standardized state, previous applied action (normalized)];
    # the MLP head then consumes [standardized state, hidden]. norm_mean/norm_std cover
    # ONLY the state part (state_feat_dim); the hidden vector is fed unnormalized.
    gru_w_ih: np.ndarray | None = None
    gru_w_hh: np.ndarray | None = None
    gru_b_ih: np.ndarray | None = None
    gru_b_hh: np.ndarray | None = None

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

    @property
    def recurrent(self) -> bool:
        return self.gru_w_ih is not None

    @property
    def hidden_dim(self) -> int:
        """GRU hidden width (0 on a feedforward policy)."""
        return 0 if not self.recurrent else int(self.gru_w_hh.shape[1])

    @property
    def state_feat_dim(self) -> int:
        """Normalized-state width. For a feedforward policy == input_dim; for a
        recurrent policy the MLP input is [state, hidden] so it's input_dim - hidden."""
        return self.input_dim - self.hidden_dim

    def _kinds(self) -> tuple[str, ...]:
        return self.action_kinds or ("continuous",) * self.output_width

    def _standardize_state(self, states: np.ndarray) -> np.ndarray:
        """Standardize the state part with the exported normalizer (std floored)."""
        std = np.where(self.norm_std == 0.0, 1.0, self.norm_std)
        return (states.astype(np.float32) - self.norm_mean) / std

    def _forward_norm(self, mlp_input: np.ndarray) -> np.ndarray:
        """Raw network output (per-dim heads, pre-decode) for a prepared MLP input."""
        x = mlp_input.astype(np.float32)
        n = len(self.layers)
        for i, (W, b) in enumerate(self.layers):
            x = x @ W.T + b
            if i < n - 1:
                x = np.maximum(x, 0.0)  # ReLU
        return x

    def _decode(self, out: np.ndarray) -> np.ndarray:
        """Map raw network output (N, output_width) -> (N, A) de-normalized actions.

        Walks the flat output positionally per dim: continuous -> clamp+denorm,
        categorical -> argmax over its logits mapped back to the category value.
        """
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

    def act_batch(self, states: np.ndarray) -> np.ndarray:
        """Map raw (un-normalized) state rows -> (N, A) de-normalized actions.

        Feedforward path (context-free). For a recurrent policy this treats each row
        as an isolated first window (zero hidden); use ``act_sequence`` to carry the
        episode context that makes the policy adapt.
        """
        z = self._standardize_state(states)
        if self.recurrent:
            h = np.zeros((z.shape[0], self.hidden_dim), dtype=np.float32)
            z = np.concatenate([z, h], axis=1)
        return self._decode(self._forward_norm(z))

    def _gru_step(self, h: np.ndarray, token: np.ndarray) -> np.ndarray:
        """One torch.nn.GRUCell step. h (N,H), token (N,T) -> h' (N,H)."""
        H = self.hidden_dim
        gi = token @ self.gru_w_ih.T + self.gru_b_ih  # (N, 3H)
        gh = h @ self.gru_w_hh.T + self.gru_b_hh       # (N, 3H)
        r = _sigmoid(gi[:, :H] + gh[:, :H])
        z = _sigmoid(gi[:, H:2 * H] + gh[:, H:2 * H])
        n = np.tanh(gi[:, 2 * H:] + r * gh[:, 2 * H:])
        return ((1.0 - z) * n + z * h).astype(np.float32)

    def act_sequence(self, states_raw: np.ndarray, actions_norm: np.ndarray,
                     next_states_raw: np.ndarray | None = None):
        """Roll the recurrent policy over one episode's windows in order.

        ``states_raw`` (L, S) are the per-window raw states; ``actions_norm`` (L, A)
        the normalized action APPLIED at each window (the token's action part). The
        hidden state starts at zero and is advanced by the GRU after each window using
        the token [standardized state, applied action], so the action proposed at
        window i sees the history of windows < i — exactly what ``rl_policy.cpp`` does
        online. Returns (L, A) de-normalized actions at each state; if
        ``next_states_raw`` is given, also returns the (L, A) actions at the next
        states (the policy's pi(s') for the FQE bootstrap), a tuple ``(a_s, a_s2)``.
        """
        if not self.recurrent:
            raise ValueError("act_sequence requires a recurrent policy")
        L = states_raw.shape[0]
        H = self.hidden_dim
        s_std = self._standardize_state(states_raw)
        s2_std = None if next_states_raw is None else self._standardize_state(next_states_raw)
        a_s = np.empty((L, self.action_dim), dtype=np.float32)
        a_s2 = None if s2_std is None else np.empty((L, self.action_dim), dtype=np.float32)
        h = np.zeros((1, H), dtype=np.float32)
        for i in range(L):
            a_s[i] = self._decode(self._forward_norm(
                np.concatenate([s_std[i:i + 1], h], axis=1)))[0]
            token = np.concatenate([s_std[i:i + 1], actions_norm[i:i + 1]], axis=1)
            h_next = self._gru_step(h, token)
            if a_s2 is not None:
                a_s2[i] = self._decode(self._forward_norm(
                    np.concatenate([s2_std[i:i + 1], h_next], axis=1)))[0]
            h = h_next
        return a_s if a_s2 is None else (a_s, a_s2)

    def act(self, state: np.ndarray) -> float:
        """The primary (rps) setpoint for one raw state."""
        return float(self.act_batch(state[None, :])[0, 0])

    def act_vector(self, state: np.ndarray) -> np.ndarray:
        """The full (A,) action vector for one raw state."""
        return self.act_batch(state[None, :])[0]
