"""Flat weight-file (de)serialization — the Python↔C++ handshake.

The trained ``PolicyArtifact`` is written as a self-describing little-endian binary
that ``rl_policy.cpp`` reads with no torch, no JSON, no external deps. This module
is the single source of truth for that byte layout; the C++ loader must match it.

Layout (all little-endian):

    magic      : 4 bytes  = b"SRLP"
    version    : uint32   = 1
    in_dim     : uint32
    n_layers   : uint32                      # includes the output layer
    out_dims   : uint32 * n_layers           # per-layer output width
    for each layer L (in order):
        W_L    : float32 * (out_dim_L * in_dim_L)   # row-major (out, in)
        b_L    : float32 * out_dim_L
    norm_mean  : float32 * in_dim
    norm_std   : float32 * in_dim
    action_lo  : float32
    action_hi  : float32

Activations are implied by position: ReLU on every layer except the last, which is
linear then clamped to [0,1] and de-normalized with (action_lo, action_hi).
"""

from __future__ import annotations

import struct
from pathlib import Path

import numpy as np

from .policy_artifact import PolicyArtifact

_MAGIC = b"SRLP"
_VERSION = 1


def save_policy(artifact: PolicyArtifact, path: str | Path) -> None:
    layers = artifact.layers
    in_dim = int(layers[0][0].shape[1])
    out_dims = [int(W.shape[0]) for W, _ in layers]

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
    buf += struct.pack("<ff", float(artifact.action_lo), float(artifact.action_hi))

    Path(path).write_bytes(bytes(buf))


def load_policy(path: str | Path, feature_names: tuple[str, ...] = ()) -> PolicyArtifact:
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
    action_lo, action_hi = struct.unpack_from("<ff", raw, off)

    return PolicyArtifact(
        layers=layers,
        norm_mean=norm_mean,
        norm_std=norm_std,
        action_lo=float(action_lo),
        action_hi=float(action_hi),
        feature_names=tuple(feature_names),
    )
