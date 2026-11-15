"""Flat weight-file (de)serialization — the Python↔C++ handshake.

The trained ``PolicyArtifact`` is written as a self-describing little-endian binary
that ``rl_policy.cpp`` reads with no torch, no JSON, no external deps. This module
is the single source of truth for that byte layout; the C++ loader must match it.

Layout (all little-endian):

    magic      : 4 bytes  = b"SRLP"
    version    : uint32   = 2 or 3
    in_dim     : uint32
    n_layers   : uint32                      # includes the output layer
    out_dims   : uint32 * n_layers           # per-layer output width; last == OUTPUT width
    for each layer L (in order):
        W_L    : float32 * (out_dim_L * in_dim_L)   # row-major (out, in)
        b_L    : float32 * out_dim_L
    norm_mean  : float32 * in_dim
    norm_std   : float32 * in_dim
    action_dim : uint32                      # number of action DIMENSIONS

  v2 footer (all dims continuous; output width == action_dim):
    action_lo  : float32 * action_dim        # per-dim lower bound
    action_hi  : float32 * action_dim        # per-dim upper bound

  v3 footer (mixed heads; output width == sum of per-dim head widths):
    for each dim k:
        kind   : uint32                      # 0 = continuous, 1 = categorical
        if continuous: lo:float32, hi:float32
        if categorical: n_cat:uint32, cats:float32 * n_cat   # category value per class

Activations are implied by position: ReLU on every layer except the last. The last
layer is decoded per dim in order (the wire contract; see action_spec.ActionSpec):
a continuous dim reads one output, clamps to [0,1], de-normalizes with (lo, hi); a
categorical dim reads n_cat outputs as logits and maps argmax -> cats[idx].

v4 (RL² recurrent) has a DIFFERENT top-level layout — a GRU context encoder runs
once per window and its hidden state is carried across the episode, so the MLP input
is [standardized state, hidden] and the state normalizer covers only the state part:

    magic      : 4 bytes = b"SRLP"
    version    : uint32   = 4
    state_dim  : uint32                      # normalized state width (norm length)
    hidden_dim : uint32   = H
    action_dim : uint32   = A (dimensions)
    gru_w_ih   : float32 * (3H * (state_dim + A))   # torch GRUCell, gate order r,z,n
    gru_w_hh   : float32 * (3H * H)
    gru_b_ih   : float32 * (3H)
    gru_b_hh   : float32 * (3H)
    n_layers   : uint32
    out_dims   : uint32 * n_layers           # first MLP layer in-dim == state_dim + H
    per layer  : W (float32, out*in), b (float32, out)
    norm_mean  : float32 * state_dim
    norm_std   : float32 * state_dim
    v3-style per-dim head footer (continuous lo/hi or categorical n_cat+cats)
"""

from __future__ import annotations

import struct
from pathlib import Path

import numpy as np

from .policy_artifact import PolicyArtifact

_MAGIC = b"SRLP"
_KIND_CONTINUOUS = 0
_KIND_CATEGORICAL = 1


def _has_categorical(artifact: PolicyArtifact) -> bool:
    return bool(artifact.action_kinds) and any(
        k == "categorical" for k in artifact.action_kinds
    )


def _write_head_footer(buf: bytearray, artifact: PolicyArtifact,
                       action_lo: np.ndarray, action_hi: np.ndarray) -> None:
    """Append the v3-style per-dim head footer (shared by v3 and v4)."""
    for k, kind in enumerate(artifact.action_kinds):
        if kind == "categorical":
            cats = np.ascontiguousarray(artifact.action_categories[k], dtype="<f4")
            buf += struct.pack("<I", _KIND_CATEGORICAL)
            buf += struct.pack("<I", int(cats.size))
            buf += cats.tobytes()
        else:
            buf += struct.pack("<I", _KIND_CONTINUOUS)
            buf += struct.pack("<ff", float(action_lo[k]), float(action_hi[k]))


def _save_recurrent(artifact: PolicyArtifact, path: str | Path) -> None:
    """Write an RL² recurrent policy (SRLP v4). See the module docstring for bytes."""
    layers = artifact.layers
    state_dim = int(np.asarray(artifact.norm_mean).size)
    hidden = int(artifact.hidden_dim)
    a_dim = int(np.atleast_1d(artifact.action_lo).size)
    token = state_dim + a_dim
    w_ih = np.ascontiguousarray(artifact.gru_w_ih, dtype="<f4")
    w_hh = np.ascontiguousarray(artifact.gru_w_hh, dtype="<f4")
    b_ih = np.ascontiguousarray(artifact.gru_b_ih, dtype="<f4")
    b_hh = np.ascontiguousarray(artifact.gru_b_hh, dtype="<f4")
    if w_ih.shape != (3 * hidden, token):
        raise ValueError(f"gru_w_ih {w_ih.shape} != {(3 * hidden, token)}")
    if w_hh.shape != (3 * hidden, hidden):
        raise ValueError(f"gru_w_hh {w_hh.shape} != {(3 * hidden, hidden)}")
    if b_ih.size != 3 * hidden or b_hh.size != 3 * hidden:
        raise ValueError("gru bias sizes must be 3*hidden")
    if int(layers[0][0].shape[1]) != state_dim + hidden:
        raise ValueError(
            f"first MLP layer in-dim {layers[0][0].shape[1]} != state_dim+hidden "
            f"{state_dim + hidden}")
    if not _has_categorical(artifact) and not artifact.action_kinds:
        raise ValueError("recurrent export requires explicit per-dim action_kinds")

    out_dims = [int(W.shape[0]) for W, _ in layers]
    # Validate output width == sum of head widths.
    expect = 0
    for k, kind in enumerate(artifact.action_kinds):
        expect += int(np.asarray(artifact.action_categories[k]).size) if kind == "categorical" else 1
    if out_dims[-1] != expect:
        raise ValueError(f"output width {out_dims[-1]} != sum of head widths {expect}")

    buf = bytearray()
    buf += _MAGIC
    buf += struct.pack("<IIII", 4, state_dim, hidden, a_dim)
    buf += w_ih.tobytes()
    buf += w_hh.tobytes()
    buf += b_ih.tobytes()
    buf += b_hh.tobytes()
    buf += struct.pack("<I", len(layers))
    buf += struct.pack(f"<{len(out_dims)}I", *out_dims)
    prev = state_dim + hidden
    for W, b in layers:
        out = int(W.shape[0])
        if W.shape != (out, prev):
            raise ValueError(f"layer shape {W.shape} != expected {(out, prev)}")
        buf += np.ascontiguousarray(W, dtype="<f4").tobytes()
        buf += np.ascontiguousarray(b, dtype="<f4").tobytes()
        prev = out
    buf += np.ascontiguousarray(artifact.norm_mean, dtype="<f4").tobytes()
    buf += np.ascontiguousarray(artifact.norm_std, dtype="<f4").tobytes()
    action_lo = np.atleast_1d(np.asarray(artifact.action_lo, dtype="<f4"))
    action_hi = np.atleast_1d(np.asarray(artifact.action_hi, dtype="<f4"))
    _write_head_footer(buf, artifact, action_lo, action_hi)
    Path(path).write_bytes(bytes(buf))


def save_policy(artifact: PolicyArtifact, path: str | Path) -> None:
    if artifact.recurrent:
        _save_recurrent(artifact, path)
        return
    layers = artifact.layers
    in_dim = int(layers[0][0].shape[1])
    out_dims = [int(W.shape[0]) for W, _ in layers]
    action_lo = np.atleast_1d(np.asarray(artifact.action_lo, dtype="<f4"))
    action_hi = np.atleast_1d(np.asarray(artifact.action_hi, dtype="<f4"))
    a_dim = int(action_lo.size)

    categorical = _has_categorical(artifact)
    version = 3 if categorical else 2

    # Validate the output width matches the sum of per-dim head widths.
    if categorical:
        kinds = artifact.action_kinds
        expect = 0
        for k, kind in enumerate(kinds):
            expect += int(np.asarray(artifact.action_categories[k]).size) if kind == "categorical" else 1
        if out_dims[-1] != expect:
            raise ValueError(f"output width {out_dims[-1]} != sum of head widths {expect}")
        if action_hi.size != a_dim or len(kinds) != a_dim:
            raise ValueError("action_dim mismatch across lo/hi/kinds")
    else:
        if out_dims[-1] != a_dim or action_hi.size != a_dim:
            raise ValueError(f"action_dim mismatch: out={out_dims[-1]} lo={a_dim} hi={action_hi.size}")

    buf = bytearray()
    buf += _MAGIC
    buf += struct.pack("<III", version, in_dim, len(layers))
    buf += struct.pack(f"<{len(out_dims)}I", *out_dims)

    prev = in_dim
    for W, b in layers:
        out = int(W.shape[0])
        if W.shape != (out, prev):
            raise ValueError(f"layer shape {W.shape} != expected {(out, prev)}")
        buf += np.ascontiguousarray(W, dtype="<f4").tobytes()
        buf += np.ascontiguousarray(b, dtype="<f4").tobytes()
        prev = out

    buf += np.ascontiguousarray(artifact.norm_mean, dtype="<f4").tobytes()
    buf += np.ascontiguousarray(artifact.norm_std, dtype="<f4").tobytes()
    buf += struct.pack("<I", a_dim)

    if not categorical:
        buf += action_lo.tobytes()
        buf += action_hi.tobytes()
    else:
        for k, kind in enumerate(artifact.action_kinds):
            if kind == "categorical":
                cats = np.ascontiguousarray(artifact.action_categories[k], dtype="<f4")
                buf += struct.pack("<I", _KIND_CATEGORICAL)
                buf += struct.pack("<I", int(cats.size))
                buf += cats.tobytes()
            else:
                buf += struct.pack("<I", _KIND_CONTINUOUS)
                buf += struct.pack("<ff", float(action_lo[k]), float(action_hi[k]))

    Path(path).write_bytes(bytes(buf))


def _read_head_footer(raw: bytes, off: int, a_dim: int):
    """Parse the v3-style per-dim head footer -> (lo, hi, kinds, categories, off)."""
    lo = np.zeros(a_dim, dtype=np.float32)
    hi = np.ones(a_dim, dtype=np.float32)
    kinds: list[str] = []
    cats_list: list = []
    for k in range(a_dim):
        (kind,) = struct.unpack_from("<I", raw, off)
        off += 4
        if kind == _KIND_CATEGORICAL:
            (n_cat,) = struct.unpack_from("<I", raw, off)
            off += 4
            cats = np.frombuffer(raw, dtype="<f4", count=n_cat, offset=off).copy()
            off += 4 * n_cat
            kinds.append("categorical")
            cats_list.append(cats)
            if n_cat:
                lo[k] = float(cats.min())
                hi[k] = float(cats.max() if cats.max() > cats.min() else cats.min() + 1.0)
        else:
            l, h = struct.unpack_from("<ff", raw, off)
            off += 8
            kinds.append("continuous")
            cats_list.append(None)
            lo[k], hi[k] = l, h
    return lo, hi, tuple(kinds), tuple(cats_list), off


def _load_recurrent(raw: bytes, off: int, feature_names: tuple[str, ...],
                    action_names: tuple[str, ...]) -> PolicyArtifact:
    """Parse an SRLP v4 recurrent policy (see module docstring)."""
    state_dim, hidden, a_dim = struct.unpack_from("<III", raw, off)
    off += 12
    token = state_dim + a_dim
    n_ih = 3 * hidden * token
    w_ih = np.frombuffer(raw, dtype="<f4", count=n_ih, offset=off).reshape(3 * hidden, token).copy()
    off += 4 * n_ih
    n_hh = 3 * hidden * hidden
    w_hh = np.frombuffer(raw, dtype="<f4", count=n_hh, offset=off).reshape(3 * hidden, hidden).copy()
    off += 4 * n_hh
    b_ih = np.frombuffer(raw, dtype="<f4", count=3 * hidden, offset=off).copy()
    off += 4 * 3 * hidden
    b_hh = np.frombuffer(raw, dtype="<f4", count=3 * hidden, offset=off).copy()
    off += 4 * 3 * hidden

    (n_layers,) = struct.unpack_from("<I", raw, off)
    off += 4
    out_dims = list(struct.unpack_from(f"<{n_layers}I", raw, off))
    off += 4 * n_layers
    layers: list[tuple[np.ndarray, np.ndarray]] = []
    prev = state_dim + hidden
    for out in out_dims:
        n_w = out * prev
        W = np.frombuffer(raw, dtype="<f4", count=n_w, offset=off).reshape(out, prev).copy()
        off += 4 * n_w
        b = np.frombuffer(raw, dtype="<f4", count=out, offset=off).copy()
        off += 4 * out
        layers.append((W, b))
        prev = out

    norm_mean = np.frombuffer(raw, dtype="<f4", count=state_dim, offset=off).copy()
    off += 4 * state_dim
    norm_std = np.frombuffer(raw, dtype="<f4", count=state_dim, offset=off).copy()
    off += 4 * state_dim
    action_lo, action_hi, kinds, cats, off = _read_head_footer(raw, off, a_dim)

    return PolicyArtifact(
        layers=layers,
        norm_mean=norm_mean,
        norm_std=norm_std,
        action_lo=action_lo,
        action_hi=action_hi,
        feature_names=tuple(feature_names),
        action_names=tuple(action_names),
        action_kinds=kinds,
        action_categories=cats,
        gru_w_ih=w_ih,
        gru_w_hh=w_hh,
        gru_b_ih=b_ih,
        gru_b_hh=b_hh,
    )


def load_policy(path: str | Path, feature_names: tuple[str, ...] = (),
                action_names: tuple[str, ...] = ("rps",)) -> PolicyArtifact:
    raw = Path(path).read_bytes()
    off = 0

    magic = raw[off:off + 4]
    off += 4
    if magic != _MAGIC:
        raise ValueError(f"bad magic {magic!r} (not a SRLP policy file)")
    (version,) = struct.unpack_from("<I", raw, off)
    if version == 4:
        return _load_recurrent(raw, off + 4, tuple(feature_names), tuple(action_names))
    version, in_dim, n_layers = struct.unpack_from("<III", raw, off)
    off += 12
    if version not in (2, 3):
        raise ValueError(f"unsupported policy version {version}")
    out_dims = list(struct.unpack_from(f"<{n_layers}I", raw, off))
    off += 4 * n_layers

    layers: list[tuple[np.ndarray, np.ndarray]] = []
    prev = in_dim
    for out in out_dims:
        n_w = out * prev
        W = np.frombuffer(raw, dtype="<f4", count=n_w, offset=off).reshape(out, prev).copy()
        off += 4 * n_w
        b = np.frombuffer(raw, dtype="<f4", count=out, offset=off).copy()
        off += 4 * out
        layers.append((W, b))
        prev = out

    norm_mean = np.frombuffer(raw, dtype="<f4", count=in_dim, offset=off).copy()
    off += 4 * in_dim
    norm_std = np.frombuffer(raw, dtype="<f4", count=in_dim, offset=off).copy()
    off += 4 * in_dim
    (a_dim,) = struct.unpack_from("<I", raw, off)
    off += 4

    action_kinds: tuple[str, ...] = ()
    action_categories: tuple = ()
    if version == 2:
        action_lo = np.frombuffer(raw, dtype="<f4", count=a_dim, offset=off).copy()
        off += 4 * a_dim
        action_hi = np.frombuffer(raw, dtype="<f4", count=a_dim, offset=off).copy()
    else:
        lo = np.zeros(a_dim, dtype=np.float32)
        hi = np.ones(a_dim, dtype=np.float32)
        kinds: list[str] = []
        cats_list: list = []
        for k in range(a_dim):
            (kind,) = struct.unpack_from("<I", raw, off)
            off += 4
            if kind == _KIND_CATEGORICAL:
                (n_cat,) = struct.unpack_from("<I", raw, off)
                off += 4
                cats = np.frombuffer(raw, dtype="<f4", count=n_cat, offset=off).copy()
                off += 4 * n_cat
                kinds.append("categorical")
                cats_list.append(cats)
                if n_cat:
                    lo[k] = float(cats.min())
                    hi[k] = float(cats.max() if cats.max() > cats.min() else cats.min() + 1.0)
            else:
                l, h = struct.unpack_from("<ff", raw, off)
                off += 8
                kinds.append("continuous")
                cats_list.append(None)
                lo[k], hi[k] = l, h
        action_lo, action_hi = lo, hi
        action_kinds = tuple(kinds)
        action_categories = tuple(cats_list)

    return PolicyArtifact(
        layers=layers,
        norm_mean=norm_mean,
        norm_std=norm_std,
        action_lo=action_lo,
        action_hi=action_hi,
        feature_names=tuple(feature_names),
        action_names=tuple(action_names),
        action_kinds=action_kinds,
        action_categories=action_categories,
    )
