"""Flat weight-file (de)serialization — the Python↔C++ handshake.

The trained ``PolicyArtifact`` is written as a self-describing little-endian binary
that ``rl_policy.cpp`` reads with no torch, no JSON, no external deps. This module
is the single source of truth for that byte layout; the C++ loader must match it.

Layout (all little-endian):

    magic      : 4 bytes  = b"SRLP"
    version    : uint32   = 2
    in_dim     : uint32
    n_layers   : uint32                      # includes the output layer
    out_dims   : uint32 * n_layers           # per-layer output width; last == action_dim
    for each layer L (in order):
        W_L    : float32 * (out_dim_L * in_dim_L)   # row-major (out, in)
        b_L    : float32 * out_dim_L
    norm_mean  : float32 * in_dim
    norm_std   : float32 * in_dim
    action_dim : uint32
    action_lo  : float32 * action_dim        # per-dim lower bound
    action_hi  : float32 * action_dim        # per-dim upper bound

Activations are implied by position: ReLU on every layer except the last, which is
linear then per-dim clamped to [0,1] and de-normalized with (action_lo, action_hi).
The action dimension order is the wire contract (see action_spec.ActionSpec); the
serving side applies the outputs positionally, so names are not stored here.
"""

from __future__ import annotations

import struct
from pathlib import Path

import numpy as np

from .policy_artifact import PolicyArtifact

_MAGIC = b"SRLP"
_VERSION = 2


def save_policy(artifact: PolicyArtifact, path: str | Path) -> None:
    layers = artifact.layers
    in_dim = int(layers[0][0].shape[1])
    out_dims = [int(W.shape[0]) for W, _ in layers]
    action_lo = np.atleast_1d(np.asarray(artifact.action_lo, dtype="<f4"))
    action_hi = np.atleast_1d(np.asarray(artifact.action_hi, dtype="<f4"))
    a_dim = int(action_lo.size)
    if out_dims[-1] != a_dim or action_hi.size != a_dim:
        raise ValueError(f"action_dim mismatch: out={out_dims[-1]} lo={a_dim} hi={action_hi.size}")

    buf = bytearray()
    buf += _MAGIC
    buf += struct.pack("<III", _VERSION, in_dim, len(layers))
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
    buf += action_lo.tobytes()
    buf += action_hi.tobytes()

    Path(path).write_bytes(bytes(buf))


def load_policy(path: str | Path, feature_names: tuple[str, ...] = (),
                action_names: tuple[str, ...] = ("rps",)) -> PolicyArtifact:
    raw = Path(path).read_bytes()
    off = 0

    magic = raw[off:off + 4]
    off += 4
    if magic != _MAGIC:
        raise ValueError(f"bad magic {magic!r} (not a SRLP policy file)")
    version, in_dim, n_layers = struct.unpack_from("<III", raw, off)
    off += 12
    if version != _VERSION:
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
    action_lo = np.frombuffer(raw, dtype="<f4", count=a_dim, offset=off).copy()
    off += 4 * a_dim
    action_hi = np.frombuffer(raw, dtype="<f4", count=a_dim, offset=off).copy()

    return PolicyArtifact(
        layers=layers,
        norm_mean=norm_mean,
        norm_std=norm_std,
        action_lo=action_lo,
        action_hi=action_hi,
        feature_names=tuple(feature_names),
        action_names=tuple(action_names),
    )
