"""Minimal JWT HS256 verification helpers for control-plane auth."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def _b64url_decode(raw: str) -> bytes:
    text = str(raw or "").strip()
    if not text:
        return b""
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data or b"")).decode("ascii").rstrip("=")


def decode_jwt_hs256(token: str, secret: str, *, verify_exp: bool = True) -> dict:
    """Decode and verify HS256 JWT; raises ValueError on failure."""
    raw = str(token or "").strip()
    key = str(secret or "").encode("utf-8")
    if not raw:
        raise ValueError("empty token")
    parts = raw.split(".")
    if len(parts) != 3:
        raise ValueError("invalid jwt format")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(_b64url_decode(h_b64).decode("utf-8"))
    payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
    alg = str((dict(header or {})).get("alg", "") or "").strip().upper()
    if alg != "HS256":
        raise ValueError("unsupported jwt alg")
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    provided_sig = _b64url_decode(s_b64)
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("jwt signature mismatch")
    if verify_exp:
        now = int(time.time())
        exp = (dict(payload or {})).get("exp")
        nbf = (dict(payload or {})).get("nbf")
        if exp is not None and int(exp) < now:
            raise ValueError("jwt expired")
        if nbf is not None and int(nbf) > now:
            raise ValueError("jwt not yet valid")
    return dict(payload or {})


def encode_jwt_hs256(payload: dict, secret: str) -> str:
    """Utility for tests."""
    hdr = {"alg": "HS256", "typ": "JWT"}
    h_b64 = _b64url_encode(json.dumps(hdr, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(dict(payload or {}), separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(str(secret or "").encode("utf-8"), signing_input, hashlib.sha256).digest()
    s_b64 = _b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{s_b64}"
