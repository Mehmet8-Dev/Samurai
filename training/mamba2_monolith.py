#!/usr/bin/env python3
from __future__ import annotations

"""Single-file Mamba-2 training, dataset, eval, resume and inference pipeline."""

# Bu hucre notebook'un tum monolitik cekirdegini tasir.
# Amac: proje icindeki daginik Mamba entegrasyonunu tek dosyada toplamak.
# Buradaki kod; veri okuma, tokenizasyon, model, egitim, checkpoint ve inference
# icin gereken cekirdek yuzeyi tek yerde tanimlar.

import copy
import hashlib
import json
import math
import os
import random
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Literal, Optional, Sequence, Tuple

import torch
import torch.nn as nn

# Dis bagimliliklar burada acikca fail-fast davranir.
# Notebook yarim yuklenip sonradan anlamsiz hata vermesin diye,
# eksik kutuphaneler hucrenin basinda net bir RuntimeError uretir.
try:
    import yaml
except Exception as exc:
    raise RuntimeError('pyyaml gerekli: pip install pyyaml') from exc

try:
    import pandas as pd
except Exception as exc:
    raise RuntimeError('pandas gerekli: pip install pandas') from exc

try:
    from mamba_ssm import Mamba  # type: ignore
except Exception:
    try:
        from mamba_ssm.modules.mamba_simple import Mamba  # type: ignore
    except Exception as exc:
        raise RuntimeError('mamba-ssm gerekli: pip install mamba-ssm') from exc

try:
    import mamba_ssm.modules.mamba_simple as _mamba_simple_mod  # type: ignore
    import mamba_ssm.ops.selective_scan_interface as _ssi  # type: ignore

    # Mamba wheel'i bazen sadece CUDA kernel ile gelir.
    # CPU tensor'lerinde referans uygulamaya dusen bir dispatch koyuyoruz.
    # Bu sayede notebook hem CPU smoke testlerinde hem de CUDA egitimde calisabilir.
    _orig_selective_scan_fn = _ssi.selective_scan_fn

    def _selective_scan_dispatch(
        u,
        delta,
        A,
        B,
        C,
        D=None,
        z=None,
        delta_bias=None,
        delta_softplus=False,
        return_last_state=False,
    ):
        if getattr(u, 'is_cuda', False):
            return _orig_selective_scan_fn(
                u,
                delta,
                A,
                B,
                C,
                D=D,
                z=z,
                delta_bias=delta_bias,
                delta_softplus=delta_softplus,
                return_last_state=return_last_state,
            )
        return _ssi.selective_scan_ref(
            u,
            delta,
            A,
            B,
            C,
            D=D,
            z=z,
            delta_bias=delta_bias,
            delta_softplus=delta_softplus,
            return_last_state=return_last_state,
        )

    _ssi.selective_scan_fn = _selective_scan_dispatch
    _mamba_simple_mod.selective_scan_fn = _selective_scan_dispatch
except Exception:
    pass

SUPPORTED_PROTOCOLS = {'http1', 'http2', 'websocket', 'quic'}
SUPPORTED_LABELS = {'benign', 'evasive', 'aggressive'}
SUPPORTED_EVENT_TYPES = {
    'connect_open',
    'tls_client_hello',
    'http_request',
    'http2_headers',
    'ws_open',
    'ws_frame',
    'quic_open',
    'quic_request',
    'idle_wait',
    'retry',
    'reset',
    'close',
}
PROTOCOL_EVENT_TYPES = {
    'http1': {'connect_open', 'tls_client_hello', 'http_request', 'idle_wait', 'retry', 'reset', 'close'},
    'http2': {'connect_open', 'tls_client_hello', 'http2_headers', 'idle_wait', 'retry', 'reset', 'close'},
    'websocket': {'connect_open', 'tls_client_hello', 'ws_open', 'ws_frame', 'idle_wait', 'retry', 'reset', 'close'},
    'quic': {'connect_open', 'quic_open', 'quic_request', 'idle_wait', 'retry', 'reset', 'close'},
}

PAD_TOKEN = '<pad>'
BOS_TOKEN = '<bos>'
EOS_TOKEN = '<eos>'
PROTO_PREFIX = 'PROTO:'
LABEL_PREFIX = 'LABEL:'
EVT_PREFIX = 'EVT:'
DELAY_PREFIX = 'DELAY:'
METHOD_PREFIX = 'METHOD:'
PATH_PREFIX = 'PATH:'
HEADER_PREFIX = 'HEADER:'
PAYLOAD_PREFIX = 'PAYLOAD:'
MUTATION_PREFIX = 'MUTATION:'

KNOWN_DELAY_BUCKETS = ['none', '0_5ms', '6_20ms', '21_100ms', '101_500ms', '500ms_plus']
KNOWN_METHODS = ['none', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options']
KNOWN_PATH_BUCKETS = ['root', 'api', 'ws', 'static', 'auth', 'search', 'media', 'other']
KNOWN_HEADER_PROFILES = ['none', 'unknown', 'modern_browser', 'api_json', 'generic_http', 'http_csv', 'h2_csv', 'quic_csv', 'quic']
KNOWN_PAYLOAD_CLASSES = ['none', 'empty', 'tiny', 'small', 'medium', 'large']
KNOWN_MUTATION_SIGNATURES = ['none', 'csv_attack_label', 'header_shuffle', 'retry_burst', 'header_shuffle|retry_burst']


@dataclass(frozen=True)
class EventRecord:
    event_type: str
    delay_bucket: str = 'none'
    method: str = 'none'
    path_bucket: str = 'other'
    header_profile: str = 'none'
    payload_class: str = 'none'
    mutation_signature: str = 'none'


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    protocol: str
    label: str
    events: List[EventRecord]


@dataclass(frozen=True)
class SessionEvent:
    step_index: int
    event_type: str
    delay_ms: int = 0
    method: Optional[str] = None
    path: Optional[str] = None
    header_profile: Optional[str] = None
    payload_class: Optional[str] = None
    mutation_flags: List[str] = field(default_factory=list)
    expect_response_class: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SessionPlan:
    session_id: str
    protocol: Literal['http1', 'http2', 'websocket', 'quic']
    label: Literal['benign', 'evasive', 'aggressive']
    events: List[SessionEvent]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'protocol': self.protocol,
            'label': self.label,
            'events': [ev.to_dict() for ev in self.events],
        }


@dataclass(frozen=True)
class TrafficPlan:
    plan_id: str
    model_name: str
    checkpoint_id: str
    seed: int
    session_plans: List[SessionPlan]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'plan_id': self.plan_id,
            'model_name': self.model_name,
            'checkpoint_id': self.checkpoint_id,
            'seed': int(self.seed),
            'session_plans': [sp.to_dict() for sp in self.session_plans],
        }


@dataclass
class ValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# Inference sonrasinda uretilen planlari burada tekrar dogruluyoruz.
# Sebep: model token sirasi uretse bile runtime semantigi acisindan
# protokol-event uyumu ve baslangic/bitis kurallari bozulmus olabilir.
def validate_plan(plan: TrafficPlan) -> ValidationResult:
    errors: List[str] = []
    warnings: List[str] = []
    if not str(plan.plan_id or '').strip():
        errors.append('plan_id is required')
    if not str(plan.model_name or '').strip():
        errors.append('model_name is required')
    if not plan.session_plans:
        errors.append('session_plans must be non-empty')
    for session_plan in plan.session_plans:
        if session_plan.protocol not in SUPPORTED_PROTOCOLS:
            errors.append(f'{session_plan.session_id}: unsupported protocol={session_plan.protocol}')
        if session_plan.label not in SUPPORTED_LABELS:
            errors.append(f'{session_plan.session_id}: unsupported label={session_plan.label}')
        if not session_plan.events:
            errors.append(f'{session_plan.session_id}: empty event sequence')
            continue
        if session_plan.events[0].event_type != 'connect_open':
            errors.append(f'{session_plan.session_id}: first event must be connect_open')
        if session_plan.events[-1].event_type not in {'close', 'reset'}:
            errors.append(f'{session_plan.session_id}: last event must be close|reset')
        allowed = PROTOCOL_EVENT_TYPES.get(session_plan.protocol, set())
        prev_idx = -1
        last_idx = len(session_plan.events) - 1
        for idx, ev in enumerate(session_plan.events):
            if ev.step_index != prev_idx + 1:
                errors.append(f'{session_plan.session_id}: step index jump at {ev.step_index} (prev={prev_idx})')
            if ev.event_type not in SUPPORTED_EVENT_TYPES:
                errors.append(f'{session_plan.session_id}: unsupported event_type={ev.event_type}')
            if allowed and ev.event_type not in allowed:
                errors.append(f'{session_plan.session_id}: event_type={ev.event_type} invalid for protocol={session_plan.protocol}')
            if idx > 0 and ev.event_type == 'connect_open':
                errors.append(f'{session_plan.session_id}: connect_open can only appear at step 0')
            if idx < last_idx and ev.event_type in {'close', 'reset'}:
                errors.append(f'{session_plan.session_id}: terminal event {ev.event_type} appears before final step')
            if int(ev.delay_ms) < 0:
                errors.append(f'{session_plan.session_id}: negative delay_ms={ev.delay_ms}')
            if ev.event_type in {'http_request', 'http2_headers', 'quic_request'}:
                if not str(ev.method or '').strip():
                    errors.append(f'{session_plan.session_id}: request event missing method at step={ev.step_index}')
                if not str(ev.path or '').strip():
                    errors.append(f'{session_plan.session_id}: request event missing path at step={ev.step_index}')
            prev_idx = int(ev.step_index)
    if len(plan.session_plans) < 2:
        warnings.append('very small plan: session_plans < 2')
    return ValidationResult(valid=(len(errors) == 0), errors=errors, warnings=warnings)


@dataclass(frozen=True)
class NormalizedWireEvent:
    trace_id: str
    session_id: str
    event_index: int
    timestamp_rel_ms: int
    protocol: str
    event_type: str
    label: str
    src_role: str
    method: str
    path: str
    status_class: str
    payload_class: str
    header_profile: str
    mutation_flags: str
    tls_profile: str
    h2_profile: str
    quic_mode: str
    response_time_bucket: str
    retry_count: int
    close_reason: str



import argparse
from collections import defaultdict


@dataclass(frozen=True)
class PlanRequest:
    session_count: int
    session_len: int
    seed: int
    protocols: List[str]
    label_mix: Dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class SplitResult:
    train: List[Any]
    val: List[Any]
    test: List[Any]

def _resolve_label(protocol_profile: str) -> str:
    prof = str(protocol_profile or '').strip()
    if prof.startswith('label='):
        return str(prof.split('=', 1)[1] or 'benign').strip().lower() or 'benign'
    return 'benign'


def _canonical_session_id(src_ip: str, sport: int, dst_ip: str, dport: int) -> str:
    a = (str(src_ip), int(sport))
    b = (str(dst_ip), int(dport))
    left, right = (a, b) if a <= b else (b, a)
    return f'{left[0]}:{left[1]}<->{right[0]}:{right[1]}'


def _canon(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', str(name or '').strip().lower())


def _trace_id_for_file(csv_path: str) -> str:
    p = Path(csv_path)
    h = hashlib.sha1(str(p.resolve()).encode('utf-8', errors='replace')).hexdigest()[:12]
    return f'{p.stem}-{h}'


def _to_int(v, default: int = 0) -> int:
    try:
        if v is None:
            return int(default)
        s = str(v).strip()
        if not s:
            return int(default)
        if '.' in s:
            return int(float(s))
        return int(s)
    except Exception:
        return int(default)


def _payload_class_bytes(total_bytes: int) -> str:
    n = int(total_bytes or 0)
    if n <= 0:
        return 'empty'
    if n <= 128:
        return 'tiny'
    if n <= 1024:
        return 'small'
    if n <= 8192:
        return 'medium'
    return 'large'


def _map_label(raw_label: str, default_label: str = 'benign') -> str:
    s = str(raw_label or '').strip().lower()
    if not s:
        return str(default_label or 'benign')
    if s in {'benign', 'normal'} or 'benign' in s:
        return 'benign'
    evasive_keywords = ('slowloris', 'slowhttptest', 'brute', 'infiltration', 'web attack', 'xss', 'sql', 'heartbleed', 'bot')
    if any(k in s for k in evasive_keywords):
        return 'evasive'
    return 'aggressive'


def _protocol_from_row(proto_raw, src_port: int, dst_port: int) -> str:
    p = str(proto_raw or '').strip().lower()
    if not p:
        if src_port == 443 or dst_port == 443:
            return 'http2'
        return 'http1'
    if p.isdigit():
        n = int(p)
        if n == 17:
            return 'quic' if (src_port == 443 or dst_port == 443) else 'http1'
        if n == 6:
            return 'http2' if (src_port == 443 or dst_port == 443) else 'http1'
    if p in {'udp'}:
        return 'quic' if (src_port == 443 or dst_port == 443) else 'http1'
    if p in {'tcp'}:
        return 'http2' if (src_port == 443 or dst_port == 443) else 'http1'
    if 'quic' in p:
        return 'quic'
    if 'http2' in p or p == 'h2':
        return 'http2'
    return 'http1'


def _build_colmap(columns: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for c in list(columns):
        cc = _canon(c)
        if cc and cc not in out:
            out[cc] = str(c)
    return out


def _first_non_empty(row: dict, colmap: Dict[str, str], keys: List[str], default: str = '') -> str:
    for k in keys:
        real = colmap.get(_canon(k))
        if not real:
            continue
        v = row.get(real)
        s = str(v).strip() if v is not None else ''
        if s:
            return s
    return str(default or '')


def iter_csv_normalized_events(
    csv_path: str,
    protocol_profile: str = '',
    *,
    default_label: str = 'benign',
    max_rows: int = 0,
    chunksize: int = 200000,
    progress_every: int = 0,
    progress_cb=None,
) -> Iterator[NormalizedWireEvent]:
    # CSV satirlarini dogrudan modelin tukecegi kaba event sekansina indirgeriz.
    # Burada hedef tam paket seviyesinde rekonstruksiyon degil;
    # session -> event transition mantigini ogrenebilecegimiz tutarli bir temsil uretmektir.
    file_path = str(csv_path or '').strip()
    if not file_path:
        return
    p = Path(file_path)
    if not p.exists():
        return

    trace_id = _trace_id_for_file(file_path)
    fallback_label = _resolve_label(protocol_profile) or str(default_label or 'benign')
    session_next_idx: Dict[str, int] = {}
    row_count = 0
    emitted_events = 0
    first_ts = None

    def _emit_progress(*, force: bool = False) -> None:
        if progress_cb is None:
            return
        step = max(0, int(progress_every or 0))
        if not force and (step <= 0 or row_count <= 0 or (row_count % step) != 0):
            return
        try:
            progress_cb(
                {
                    'csv_path': file_path,
                    'processed_rows': int(row_count),
                    'events_extracted': int(emitted_events),
                }
            )
        except Exception:
            pass

    reader = pd.read_csv(file_path, low_memory=False, chunksize=max(1, int(chunksize or 200000)))
    for chunk in reader:
        colmap = _build_colmap(list(chunk.columns))
        for row in chunk.to_dict(orient='records'):
            row_count += 1
            if int(max_rows or 0) > 0 and row_count > int(max_rows):
                _emit_progress(force=True)
                return

            src_ip = _first_non_empty(row, colmap, ['source ip', 'src ip'], default='0.0.0.0')
            dst_ip = _first_non_empty(row, colmap, ['destination ip', 'dst ip'], default='0.0.0.0')
            src_port = _to_int(_first_non_empty(row, colmap, ['source port', 'src port'], default='0'), default=0)
            dst_port = _to_int(_first_non_empty(row, colmap, ['destination port', 'dst port'], default='0'), default=0)
            proto_raw = _first_non_empty(row, colmap, ['protocol'], default='')
            protocol = _protocol_from_row(proto_raw, src_port, dst_port)

            row_label = _first_non_empty(row, colmap, ['label', 'attack', 'class'], default=fallback_label)
            label = _map_label(row_label, default_label=fallback_label)

            flow_id = _first_non_empty(row, colmap, ['flow id', 'flowid'], default='')
            if flow_id:
                session_id = f'flow:{flow_id}'
            else:
                if src_ip == '0.0.0.0' and dst_ip == '0.0.0.0' and src_port == 0:
                    session_id = f'row:{trace_id}:{row_count}'
                else:
                    session_id = _canonical_session_id(src_ip, src_port, dst_ip, dst_port)

            ts_raw = _first_non_empty(row, colmap, ['timestamp', 'time'], default='')
            ts_val = None
            if ts_raw:
                try:
                    ts_obj = pd.to_datetime(ts_raw, errors='coerce')
                    if hasattr(ts_obj, 'value'):
                        ts_val = float(ts_obj.value) / 1_000_000_000.0
                except Exception:
                    ts_val = None
            if ts_val is None:
                ts_val = float(row_count)
            if first_ts is None:
                first_ts = float(ts_val)
            base_rel_ms = int(max(0.0, (float(ts_val) - float(first_ts)) * 1000.0))

            syn_cnt = _to_int(_first_non_empty(row, colmap, ['syn flag cnt', 'synflagcnt'], default='0'), default=0)
            rst_cnt = _to_int(_first_non_empty(row, colmap, ['rst flag cnt', 'rstflagcnt'], default='0'), default=0)
            fin_cnt = _to_int(_first_non_empty(row, colmap, ['fin flag cnt', 'finflagcnt'], default='0'), default=0)
            fwd_bytes = _to_int(_first_non_empty(row, colmap, ['total length of fwd packets', 'totallengthoffwdpackets', 'fwd packet length total', 'fwdpacketlengthtotal'], default='0'), default=0)
            bwd_bytes = _to_int(_first_non_empty(row, colmap, ['total length of bwd packets', 'totallengthofbwdpackets', 'bwd packet length total', 'bwdpacketlengthtotal'], default='0'), default=0)
            payload_class = _payload_class_bytes(fwd_bytes + bwd_bytes)

            if protocol == 'quic':
                req_event_type = 'quic_request'
                header_profile = 'quic_csv'
                tls_profile = 'none'
                h2_profile = 'none'
                quic_mode = 'csv_inferred'
            elif protocol == 'http2':
                req_event_type = 'http2_headers'
                header_profile = 'h2_csv'
                tls_profile = 'csv_inferred'
                h2_profile = 'csv_inferred'
                quic_mode = 'none'
            else:
                req_event_type = 'http_request'
                header_profile = 'http_csv'
                tls_profile = 'none'
                h2_profile = 'none'
                quic_mode = 'none'

            mutation_flags = 'csv_attack_label' if label != 'benign' else ''
            sequence = ['connect_open', req_event_type, 'close']
            if rst_cnt > 0:
                sequence[-1] = 'reset'
            elif fin_cnt > 0:
                sequence[-1] = 'close'
            elif syn_cnt > 0:
                sequence[-1] = 'close'

            for offset, ev_type in enumerate(sequence):
                idx = int(session_next_idx.get(session_id, 0))
                session_next_idx[session_id] = idx + 1
                method = 'GET' if ev_type in {'http_request', 'http2_headers', 'quic_request'} else ''
                path = '/' if method else ''
                close_reason = 'rst' if ev_type == 'reset' else ('fin' if ev_type == 'close' else '')
                emitted_events += 1
                yield NormalizedWireEvent(
                    trace_id=trace_id,
                    session_id=session_id,
                    event_index=idx,
                    timestamp_rel_ms=int(base_rel_ms + offset),
                    protocol=protocol,
                    event_type=ev_type,
                    label=label,
                    src_role='client',
                    method=method,
                    path=path,
                    status_class='',
                    payload_class=payload_class,
                    header_profile=header_profile,
                    mutation_flags=mutation_flags,
                    tls_profile=tls_profile,
                    h2_profile=h2_profile,
                    quic_mode=quic_mode,
                    response_time_bucket='unknown',
                    retry_count=0,
                    close_reason=close_reason,
                )
            _emit_progress()
    _emit_progress(force=True)


def _delay_bucket(delta_ms: int) -> str:
    n = max(0, int(delta_ms or 0))
    if n <= 5:
        return '0_5ms'
    if n <= 20:
        return '6_20ms'
    if n <= 100:
        return '21_100ms'
    if n <= 500:
        return '101_500ms'
    return '500ms_plus'


def _path_bucket(path: str) -> str:
    p = str(path or '').strip().lower()
    if not p or p == '/':
        return 'root'
    if p.startswith('/api'):
        return 'api'
    if p.startswith('/ws'):
        return 'ws'
    if p.startswith('/static'):
        return 'static'
    if p.startswith('/login') or p.startswith('/auth'):
        return 'auth'
    if p.startswith('/search'):
        return 'search'
    if p.startswith('/image') or p.startswith('/img') or p.startswith('/media'):
        return 'media'
    return 'other'


def _mutation_signature(raw: str) -> str:
    parts = sorted({str(x).strip() for x in str(raw or '').split(',') if str(x).strip()})
    if not parts:
        return 'none'
    return '|'.join(parts)


def infer_label_from_path(path: Path) -> str:
    labels = {'benign', 'evasive', 'aggressive'}
    for part in reversed(path.parts[:-1]):
        key = str(part).strip().lower()
        if key in labels:
            return key
    return ''


def collect_csv_sources(*, csv_dir: str = '', csv_glob: str = '*.csv', csv_files: Sequence[str] | None = None) -> List[Tuple[str, Path]]:
    out: List[Tuple[str, Path]] = []
    seen: set[str] = set()
    for raw in list(csv_files or []):
        p = Path(str(raw or '').strip())
        if not p.exists() or not p.is_file():
            continue
        rp = str(p.resolve())
        if rp in seen:
            continue
        seen.add(rp)
        out.append((infer_label_from_path(p), p))
    root = Path(str(csv_dir or '').strip()) if str(csv_dir or '').strip() else None
    if root is not None and root.exists():
        for p in sorted(root.rglob(str(csv_glob or '*.csv'))):
            if not p.is_file():
                continue
            rp = str(p.resolve())
            if rp in seen:
                continue
            seen.add(rp)
            out.append((infer_label_from_path(p), p))
    return out


def load_sessions_from_csv_sources(
    sources: Sequence[Tuple[str, Path]],
    *,
    max_sessions: int = 0,
    max_rows_per_file: int = 0,
    csv_chunksize: int = 50000,
) -> Tuple[List[SessionRecord], int, int]:
    events_by_sid: Dict[str, List[Tuple[int, EventRecord]]] = {}
    meta_by_sid: Dict[str, Tuple[str, str]] = {}
    prev_ts_by_sid: Dict[str, int] = {}
    sid_order: List[str] = []
    rows_seen = 0
    files_seen = 0
    max_sess = max(0, int(max_sessions or 0))

    def _accept_sid(sid: str) -> bool:
        if sid in events_by_sid:
            return True
        if max_sess > 0 and len(events_by_sid) >= max_sess:
            return False
        events_by_sid[sid] = []
        sid_order.append(sid)
        return True

    for label_hint, csv_path in list(sources or []):
        files_seen += 1
        label_for_profile = str(label_hint or '').strip().lower()
        profile = f'label={label_for_profile}' if label_for_profile else ''
        for ev in iter_csv_normalized_events(
            str(csv_path),
            protocol_profile=profile,
            default_label=label_for_profile or 'benign',
            max_rows=int(max_rows_per_file or 0),
            chunksize=max(1, int(csv_chunksize or 50000)),
        ):
            rows_seen += 1
            sid_raw = str(getattr(ev, 'session_id', '') or '').strip()
            if not sid_raw:
                continue
            trace_id = str(getattr(ev, 'trace_id', '') or '').strip()
            sid = f'{trace_id}::{sid_raw}' if trace_id else sid_raw
            if not _accept_sid(sid):
                continue
            if sid not in meta_by_sid:
                meta_by_sid[sid] = (
                    str(getattr(ev, 'protocol', 'http1') or 'http1'),
                    str(getattr(ev, 'label', 'benign') or 'benign'),
                )
            ev_type = str(getattr(ev, 'event_type', '') or '').strip()
            if not ev_type:
                continue
            try:
                eidx = int(getattr(ev, 'event_index', 0) or 0)
            except Exception:
                eidx = 0
            ts_rel_ms = int(getattr(ev, 'timestamp_rel_ms', 0) or 0)
            prev_ts = int(prev_ts_by_sid.get(sid, ts_rel_ms))
            delay_bucket = _delay_bucket(ts_rel_ms - prev_ts if sid in prev_ts_by_sid else ts_rel_ms)
            prev_ts_by_sid[sid] = ts_rel_ms
            event = EventRecord(
                event_type=ev_type,
                delay_bucket=delay_bucket,
                method=str(getattr(ev, 'method', '') or '').strip().upper() or 'none',
                path_bucket=_path_bucket(str(getattr(ev, 'path', '') or '')),
                header_profile=str(getattr(ev, 'header_profile', '') or '').strip() or 'none',
                payload_class=str(getattr(ev, 'payload_class', '') or '').strip() or 'none',
                mutation_signature=_mutation_signature(str(getattr(ev, 'mutation_flags', '') or '')),
            )
            events_by_sid[sid].append((eidx, event))

    sessions: List[SessionRecord] = []
    for sid in sid_order:
        pairs = sorted(events_by_sid.get(sid, []), key=lambda x: int(x[0]))
        events = [ev for _i, ev in pairs if ev]
        if not events:
            continue
        protocol, label = meta_by_sid.get(sid, ('http1', 'benign'))
        sessions.append(SessionRecord(session_id=sid, protocol=protocol, label=label, events=events))
    return sessions, int(rows_seen), int(files_seen)




try:
    from scapy.all import IP, TCP, UDP, PcapReader, rdpcap  # type: ignore
except Exception:
    IP = None
    TCP = None
    UDP = None
    PcapReader = None
    rdpcap = None

_PCAP_HTTP_METHODS = {b'GET', b'POST', b'PUT', b'PATCH', b'DELETE', b'HEAD', b'OPTIONS'}
_PCAP_WEB_TCP_PORTS = {80, 8080, 8000, 443, 8443}
_PCAP_WEB_TLS_PORTS = {443, 8443}
_PCAP_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _pcap_extract_http_request(payload: bytes) -> tuple[str, str] | None:
    try:
        line = bytes(payload or b'').split(b'\r\n', 1)[0]
    except Exception:
        return None
    if not line:
        return None
    parts = line.split(b' ')
    if len(parts) < 2:
        return None
    method = parts[0].upper().strip()
    if method not in _PCAP_HTTP_METHODS:
        return None
    try:
        method_s = method.decode('ascii', errors='ignore')
        path_s = parts[1].decode('utf-8', errors='ignore') or '/'
    except Exception:
        return None
    if not path_s.startswith('/'):
        path_s = '/' + path_s
    return method_s, path_s


def _pcap_extract_http_headers(payload: bytes) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        lines = bytes(payload or b'').split(b'\r\n')
    except Exception:
        return out
    if not lines:
        return out
    for line in lines[1:]:
        if not line:
            break
        if b':' not in line:
            continue
        k, v = line.split(b':', 1)
        key = k.decode('ascii', errors='ignore').strip().lower()
        val = v.decode('utf-8', errors='ignore').strip()
        if key:
            out[key] = val
    return out


def _pcap_infer_header_profile(headers: Dict[str, str]) -> str:
    if not headers:
        return 'unknown'
    has_ua = 'user-agent' in headers
    has_accept = 'accept' in headers
    ctype = str(headers.get('content-type', '')).lower()
    if has_ua and has_accept:
        return 'modern_browser'
    if 'application/json' in ctype:
        return 'api_json'
    return 'generic_http'


def _pcap_payload_class(payload_len: int) -> str:
    n = int(payload_len or 0)
    if n <= 0:
        return 'empty'
    if n <= 64:
        return 'tiny'
    if n <= 512:
        return 'small'
    if n <= 1400:
        return 'medium'
    return 'large'


def _pcap_is_tls_client_hello(payload: bytes) -> bool:
    p = bytes(payload or b'')
    return len(p) >= 6 and p[0] == 0x16 and p[5] == 0x01


def _pcap_is_http2_preface(payload: bytes) -> bool:
    return bytes(payload or b'').startswith(_PCAP_H2_PREFACE)


def _pcap_is_quic_long_header(payload: bytes) -> bool:
    p = bytes(payload or b'')
    return len(p) >= 6 and bool((p[0] & 0x80) and (p[0] & 0x40))


def _pcap_is_quic_initial(payload: bytes) -> bool:
    p = bytes(payload or b'')
    return _pcap_is_quic_long_header(p) and (((p[0] >> 4) & 0x03) == 0)


def _pcap_infer_protocol_from_ports(sport: int, dport: int, *, is_udp: bool = False) -> str:
    if bool(is_udp) and (int(sport) in _PCAP_WEB_TLS_PORTS or int(dport) in _PCAP_WEB_TLS_PORTS):
        return 'quic'
    if int(sport) in _PCAP_WEB_TCP_PORTS or int(dport) in _PCAP_WEB_TCP_PORTS:
        return 'http2' if (int(sport) == 443 or int(dport) == 443) else 'http1'
    return 'http1'


def pcap_to_normalized_events(
    pcap_path: str,
    protocol_profile: str = '',
    *,
    max_packets: int = 0,
    progress_every: int = 0,
    progress_cb=None,
) -> List[NormalizedWireEvent]:
    if rdpcap is None or IP is None or TCP is None or UDP is None:
        return []
    pcap_file = str(pcap_path or '').strip()
    if not pcap_file:
        return []
    label = _resolve_label(protocol_profile)
    trace_id = _trace_id_for_file(pcap_file)
    first_ts = None
    session_next_idx: Dict[str, int] = defaultdict(int)
    out: List[NormalizedWireEvent] = []
    processed_packets = 0
    max_pkts = int(max_packets or 0)
    progress_step = int(progress_every or 0)

    def _progress_emit(force: bool = False) -> None:
        if progress_cb is None:
            return
        if force or (progress_step > 0 and processed_packets > 0 and (processed_packets % progress_step) == 0):
            try:
                progress_cb({'pcap_path': pcap_file, 'processed_packets': int(processed_packets), 'events_extracted': int(len(out))})
            except Exception:
                return

    packet_iter = None
    if PcapReader is not None:
        try:
            packet_iter = PcapReader(pcap_file)
        except Exception:
            packet_iter = None
    if packet_iter is None:
        try:
            packet_iter = rdpcap(pcap_file)
        except Exception:
            return []

    for pkt in packet_iter:
        processed_packets += 1
        if max_pkts > 0 and processed_packets > max_pkts:
            break
        try:
            if not pkt.haslayer(IP):
                _progress_emit()
                continue
            ip = pkt[IP]
            has_tcp = bool(pkt.haslayer(TCP))
            has_udp = bool(pkt.haslayer(UDP))
            if not has_tcp and not has_udp:
                _progress_emit()
                continue
            l4 = pkt[TCP] if has_tcp else pkt[UDP]
            sport = int(getattr(l4, 'sport', 0) or 0)
            dport = int(getattr(l4, 'dport', 0) or 0)
            payload = bytes(l4.payload) if bytes(l4.payload) else b''
            flags = int(getattr(l4, 'flags', 0) or 0) if has_tcp else 0
            protocol = _pcap_infer_protocol_from_ports(sport, dport, is_udp=has_udp)
            method = ''
            path = ''
            event_type = ''
            header_profile = 'unknown'
            payload_class = _pcap_payload_class(len(payload))
            tls_profile = 'none'
            h2_profile = 'none'
            quic_mode = 'none'
            response_time_bucket = 'unknown'
            status_class = ''
            close_reason = ''
            if payload:
                if has_tcp:
                    parsed = _pcap_extract_http_request(payload)
                    if parsed is not None:
                        method, path = parsed
                        event_type = 'http_request'
                        protocol = 'http1'
                        header_profile = _pcap_infer_header_profile(_pcap_extract_http_headers(payload))
                    elif _pcap_is_http2_preface(payload):
                        event_type = 'http2_headers'
                        protocol = 'http2'
                        h2_profile = 'preface'
                    elif _pcap_is_tls_client_hello(payload):
                        event_type = 'tls_client_hello'
                        protocol = 'http2' if dport in _PCAP_WEB_TLS_PORTS or sport in _PCAP_WEB_TLS_PORTS else protocol
                        tls_profile = 'client_hello'
                elif has_udp and (sport in _PCAP_WEB_TLS_PORTS or dport in _PCAP_WEB_TLS_PORTS) and _pcap_is_quic_long_header(payload):
                    protocol = 'quic'
                    if _pcap_is_quic_initial(payload):
                        event_type = 'quic_open'
                        quic_mode = 'initial'
                    else:
                        event_type = 'quic_request'
                        quic_mode = '1rtt'
                    header_profile = 'quic'
            if not event_type:
                if has_tcp:
                    syn = bool(flags & 0x02)
                    ack = bool(flags & 0x10)
                    fin = bool(flags & 0x01)
                    rst = bool(flags & 0x04)
                    if syn and not ack:
                        event_type = 'connect_open'
                    elif rst:
                        event_type = 'reset'
                        close_reason = 'rst'
                    elif fin:
                        event_type = 'close'
                        close_reason = 'fin'
                    else:
                        _progress_emit()
                        continue
                else:
                    _progress_emit()
                    continue
            ts = float(getattr(pkt, 'time', 0.0) or 0.0)
            if first_ts is None:
                first_ts = ts
            rel_ms = int(max(0.0, (ts - float(first_ts)) * 1000.0))
            session_id = _canonical_session_id(ip.src, sport, ip.dst, dport)
            idx = int(session_next_idx[session_id])
            session_next_idx[session_id] = idx + 1
            out.append(NormalizedWireEvent(
                trace_id=trace_id,
                session_id=session_id,
                event_index=idx,
                timestamp_rel_ms=rel_ms,
                protocol=protocol,
                event_type=event_type,
                label=label,
                src_role='client',
                method=method,
                path=path,
                status_class=status_class,
                payload_class=payload_class,
                header_profile=header_profile,
                mutation_flags='',
                tls_profile=tls_profile,
                h2_profile=h2_profile,
                quic_mode=quic_mode,
                response_time_bucket=response_time_bucket,
                retry_count=0,
                close_reason=close_reason,
            ))
            _progress_emit()
        except Exception:
            _progress_emit()
            continue
    _progress_emit(force=True)
    try:
        if hasattr(packet_iter, 'close'):
            packet_iter.close()
    except Exception:
        pass
    return out


def csv_to_normalized_events(
    csv_path: str,
    protocol_profile: str = '',
    *,
    default_label: str = 'benign',
    max_rows: int = 0,
    chunksize: int = 200000,
    progress_every: int = 0,
    progress_cb=None,
) -> List[NormalizedWireEvent]:
    return list(iter_csv_normalized_events(
        csv_path=csv_path,
        protocol_profile=protocol_profile,
        default_label=default_label,
        max_rows=max_rows,
        chunksize=chunksize,
        progress_every=progress_every,
        progress_cb=progress_cb,
    ))



def export_jsonl(rows: Iterable[Dict[str, Any]], out_path: str) -> str:
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        for row in rows:
            f.write(json.dumps(dict(row), ensure_ascii=False) + '\n')
    return out_path


def export_parquet(rows: List[Dict[str, Any]], out_path: str) -> str:
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    df = pd.DataFrame(list(rows))
    df.to_parquet(out_path, index=False)
    return out_path


def export_jsonl_to_parquet(jsonl_path: str, out_path: str, *, chunk_rows: int = 200000) -> str:
    try:
        import pyarrow as pa  # type: ignore
        import pyarrow.parquet as pq  # type: ignore
    except Exception as exc:
        raise RuntimeError('export_jsonl_to_parquet requires pyarrow to be installed') from exc
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    chunk_size = max(1, int(chunk_rows or 200000))
    writer = None
    buf: List[Dict[str, Any]] = []
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            raw = str(line or '').strip()
            if not raw:
                continue
            buf.append(json.loads(raw))
            if len(buf) < chunk_size:
                continue
            table = pa.Table.from_pylist(buf)
            if writer is None:
                writer = pq.ParquetWriter(out_path, table.schema)
            writer.write_table(table)
            buf.clear()
    if buf:
        table = pa.Table.from_pylist(buf)
        if writer is None:
            writer = pq.ParquetWriter(out_path, table.schema)
        writer.write_table(table)
    if writer is not None:
        writer.close()
    else:
        empty = pa.Table.from_pylist([])
        pq.write_table(empty, out_path)
    return out_path


def _validate_ratios(train_ratio: float, val_ratio: float) -> None:
    tr = float(train_ratio)
    vr = float(val_ratio)
    if tr <= 0.0 or tr >= 1.0:
        raise ValueError(f'train_ratio must be in (0, 1), got {train_ratio}')
    if vr <= 0.0 or vr >= 1.0:
        raise ValueError(f'val_ratio must be in (0, 1), got {val_ratio}')
    if tr + vr >= 1.0:
        raise ValueError(f'train_ratio + val_ratio must be < 1.0, got {tr + vr}')


def _target_sizes(total: int, train_ratio: float, val_ratio: float) -> tuple[int, int, int]:
    n_train = int(total * float(train_ratio))
    n_val = int(total * float(val_ratio))
    n_test = max(0, int(total) - n_train - n_val)
    return n_train, n_val, n_test


def split_dataset(items: Sequence[Any], *, seed: int = 1337, train_ratio: float = 0.8, val_ratio: float = 0.1) -> SplitResult:
    _validate_ratios(train_ratio, val_ratio)
    arr = list(items)
    rng = random.Random(int(seed))
    rng.shuffle(arr)
    n_train, n_val, _ = _target_sizes(len(arr), train_ratio, val_ratio)
    return SplitResult(train=arr[:n_train], val=arr[n_train:n_train+n_val], test=arr[n_train+n_val:])


def assign_groups_by_size(group_sizes: Mapping[str, int], *, seed: int = 1337, train_ratio: float = 0.8, val_ratio: float = 0.1) -> Dict[str, str]:
    _validate_ratios(train_ratio, val_ratio)
    sizes = {str(gid): max(0, int(size)) for gid, size in dict(group_sizes or {}).items()}
    if not sizes:
        return {}
    targets = list(_target_sizes(int(sum(sizes.values())), train_ratio, val_ratio))
    bucket_sizes = [0, 0, 0]
    split_names = ['train', 'val', 'test']
    rng = random.Random(int(seed))
    group_ids = list(sizes.keys())
    rng.shuffle(group_ids)
    group_ids.sort(key=lambda gid: sizes[gid], reverse=True)
    out: Dict[str, str] = {}
    for gid in group_ids:
        gsize = int(sizes.get(gid, 0))
        deficits = [int(targets[i]) - int(bucket_sizes[i]) for i in range(3)]
        positive = [i for i, d in enumerate(deficits) if d > 0]
        if positive:
            fit = [i for i in positive if deficits[i] >= gsize]
            candidate_pool = fit if fit else positive
            best_idx = max(candidate_pool, key=lambda i: (deficits[i], -bucket_sizes[i]))
        else:
            best_idx = min(range(3), key=lambda i: (bucket_sizes[i], i))
        out[gid] = split_names[best_idx]
        bucket_sizes[best_idx] += gsize
    return out


def split_rows_group_aware(rows: Sequence[Dict[str, Any]], *, seed: int = 1337, train_ratio: float = 0.8, val_ratio: float = 0.1, group_priority_fields: Sequence[str] = ('trace_id', 'session_id')) -> SplitResult:
    _validate_ratios(train_ratio, val_ratio)
    rr = [dict(r) for r in list(rows or [])]
    if not rr:
        return SplitResult(train=[], val=[], test=[])
    pri_fields = [str(f).strip() for f in list(group_priority_fields or []) if str(f).strip()] or ['session_id']
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for idx, row in enumerate(rr):
        gid = ''
        for field in pri_fields:
            raw = row.get(field)
            val = str(raw).strip() if raw is not None else ''
            if val:
                gid = f'{field}:{val}'
                break
        if not gid:
            gid = f'row:{idx}'
        grouped[gid].append(row)
    assign = assign_groups_by_size({gid: len(items) for gid, items in grouped.items()}, seed=seed, train_ratio=train_ratio, val_ratio=val_ratio)
    buckets = {'train': [], 'val': [], 'test': []}
    for gid, items in grouped.items():
        buckets[str(assign.get(gid, 'test'))].extend(items)
    return SplitResult(train=buckets['train'], val=buckets['val'], test=buckets['test'])


def _collect_pcaps(root: Path) -> Dict[str, List[Path]]:
    labels = ['benign', 'evasive', 'aggressive']
    out: Dict[str, List[Path]] = {}
    for label in labels:
        base = root / label
        files = []
        if base.exists():
            files = sorted(list(base.rglob('*.pcap')) + list(base.rglob('*.pcapng')))
        out[label] = files
    return out


def _collect_csv_sources(root: Path, csv_glob: str, explicit_files: List[str]) -> List[Tuple[str, Path]]:
    out: List[Tuple[str, Path]] = []
    seen: set[str] = set()
    for raw in list(explicit_files or []):
        p = Path(str(raw or '').strip())
        if not p.exists() or not p.is_file():
            continue
        rp = str(p.resolve())
        if rp in seen:
            continue
        seen.add(rp)
        out.append((infer_label_from_path(p), p))
    labels = ['benign', 'evasive', 'aggressive']
    for label in labels:
        base = root / label
        if not base.exists():
            continue
        for p in sorted(base.rglob(csv_glob)):
            if not p.is_file():
                continue
            rp = str(p.resolve())
            if rp in seen:
                continue
            seen.add(rp)
            out.append((label, p))
    if root.exists():
        for p in sorted(root.rglob(csv_glob)):
            if not p.is_file():
                continue
            rp = str(p.resolve())
            if rp in seen:
                continue
            seen.add(rp)
            out.append((infer_label_from_path(p), p))
    return out


def _overlap_count_rows(a_rows: List[dict], b_rows: List[dict], key: str) -> int:
    sa = {str(r.get(key, '') or '').strip() for r in list(a_rows or []) if str(r.get(key, '') or '').strip()}
    sb = {str(r.get(key, '') or '').strip() for r in list(b_rows or []) if str(r.get(key, '') or '').strip()}
    return 0 if (not sa or not sb) else int(len(sa & sb))


def _hash64(value: str) -> int:
    return int.from_bytes(hashlib.blake2b(str(value).encode('utf-8', errors='replace'), digest_size=8).digest(), 'big')


def _overlap_count_hashes(a: set[int], b: set[int]) -> int:
    return 0 if (not a or not b) else int(len(a & b))


def _group_id_for_row(row: Mapping[str, object], split_mode: str, event_seq: int) -> str:
    session_id = str(row.get('session_id', '') or '').strip()
    trace_id = str(row.get('trace_id', '') or '').strip()
    mode = str(split_mode or '').strip().lower()
    if mode == 'row':
        return f'row:{event_seq}'
    if mode == 'session':
        return f'session:{session_id}' if session_id else f'row:{event_seq}'
    if mode == 'trace':
        return f'trace:{trace_id}' if trace_id else f'row:{event_seq}'
    if trace_id:
        return f'trace:{trace_id}'
    if session_id:
        return f'session:{session_id}'
    return f'row:{event_seq}'


def _iter_event_dicts_for_source(*, kind: str, path: Path, label: str, max_packets: int, max_rows: int, chunksize: int, progress_every: int) -> Iterable[dict]:
    if kind == 'pcap':
        def _progress(msg: dict) -> None:
            print(f"[dataset] progress file={Path(msg.get('pcap_path', '')).name} packets={int(msg.get('processed_packets', 0))} events={int(msg.get('events_extracted', 0))}")
        events = pcap_to_normalized_events(str(path), protocol_profile=f'label={label}', max_packets=max_packets, progress_every=progress_every, progress_cb=_progress if progress_every > 0 else None)
        for ev in events:
            yield ev.to_dict()
        return
    label_for_profile = str(label or '').strip().lower()
    profile = f'label={label_for_profile}' if label_for_profile else ''
    def _progress_csv(msg: dict) -> None:
        print(f"[dataset] progress file={Path(msg.get('csv_path', '')).name} rows={int(msg.get('processed_rows', 0))} events={int(msg.get('events_extracted', 0))}")
    for ev in iter_csv_normalized_events(str(path), protocol_profile=profile, default_label=label_for_profile or 'benign', max_rows=max_rows, chunksize=chunksize, progress_every=progress_every, progress_cb=_progress_csv if progress_every > 0 else None):
        yield ev.to_dict()

class TokenCodec:
    # TokenCodec, session verisini otoregresif token dizisine cevirir.
    # Protokol ve label condition token'lari basa eklenir.
    # Her event daha sonra cok alanli olarak serialize edilir:
    # event_type, delay_bucket, method, path_bucket, header_profile,
    # payload_class ve mutation_signature.
    def __init__(self, vocab: Sequence[str]) -> None:
        vv = [str(x) for x in vocab]
        if not vv or vv[0] != PAD_TOKEN or vv[1] != BOS_TOKEN or vv[2] != EOS_TOKEN:
            raise ValueError('invalid vocabulary header')
        self.vocab: List[str] = vv
        self.token_to_id: Dict[str, int] = {t: i for i, t in enumerate(self.vocab)}
        self.pad_id = self.token_to_id[PAD_TOKEN]
        self.bos_id = self.token_to_id[BOS_TOKEN]
        self.eos_id = self.token_to_id[EOS_TOKEN]
        self.event_token_ids = [i for i, t in enumerate(self.vocab) if t.startswith(EVT_PREFIX)]
        self.delay_token_ids = [i for i, t in enumerate(self.vocab) if t.startswith(DELAY_PREFIX)]
        self.method_token_ids = [i for i, t in enumerate(self.vocab) if t.startswith(METHOD_PREFIX)]
        self.path_token_ids = [i for i, t in enumerate(self.vocab) if t.startswith(PATH_PREFIX)]
        self.header_token_ids = [i for i, t in enumerate(self.vocab) if t.startswith(HEADER_PREFIX)]
        self.payload_token_ids = [i for i, t in enumerate(self.vocab) if t.startswith(PAYLOAD_PREFIX)]
        self.mutation_token_ids = [i for i, t in enumerate(self.vocab) if t.startswith(MUTATION_PREFIX)]
        self._protocol_event_token_ids: Dict[str, List[int]] = {}
        for protocol, event_types in PROTOCOL_EVENT_TYPES.items():
            ids: List[int] = []
            for event_type in sorted(event_types):
                tok = f'{EVT_PREFIX}{event_type}'
                token_id = self.token_to_id.get(tok)
                if token_id is not None:
                    ids.append(int(token_id))
            self._protocol_event_token_ids[str(protocol)] = ids

    @classmethod
    def build(cls, sessions: Sequence[SessionRecord]) -> 'TokenCodec':
        protos = sorted({f'{PROTO_PREFIX}{p}' for p in SUPPORTED_PROTOCOLS} | {f'{PROTO_PREFIX}{s.protocol}' for s in sessions if s.protocol})
        labels = sorted({f'{LABEL_PREFIX}{l}' for l in SUPPORTED_LABELS} | {f'{LABEL_PREFIX}{s.label}' for s in sessions if s.label})
        event_types = sorted(
            {f'{EVT_PREFIX}{et}' for et in SUPPORTED_EVENT_TYPES}
            | {f'{EVT_PREFIX}{ev.event_type}' for s in sessions for ev in list(s.events or []) if getattr(ev, 'event_type', '')}
        )
        delays = sorted(
            {f'{DELAY_PREFIX}{bucket}' for bucket in KNOWN_DELAY_BUCKETS}
            | {f'{DELAY_PREFIX}{ev.delay_bucket or "none"}' for s in sessions for ev in list(s.events or [])}
        )
        methods = sorted(
            {f'{METHOD_PREFIX}{method}' for method in KNOWN_METHODS}
            | {f'{METHOD_PREFIX}{(ev.method or "none").lower()}' for s in sessions for ev in list(s.events or [])}
        )
        paths = sorted(
            {f'{PATH_PREFIX}{bucket}' for bucket in KNOWN_PATH_BUCKETS}
            | {f'{PATH_PREFIX}{ev.path_bucket or "other"}' for s in sessions for ev in list(s.events or [])}
        )
        headers = sorted(
            {f'{HEADER_PREFIX}{profile}' for profile in KNOWN_HEADER_PROFILES}
            | {f'{HEADER_PREFIX}{ev.header_profile or "none"}' for s in sessions for ev in list(s.events or [])}
        )
        payloads = sorted(
            {f'{PAYLOAD_PREFIX}{payload}' for payload in KNOWN_PAYLOAD_CLASSES}
            | {f'{PAYLOAD_PREFIX}{ev.payload_class or "none"}' for s in sessions for ev in list(s.events or [])}
        )
        mutations = sorted(
            {f'{MUTATION_PREFIX}{sig}' for sig in KNOWN_MUTATION_SIGNATURES}
            | {f'{MUTATION_PREFIX}{ev.mutation_signature or "none"}' for s in sessions for ev in list(s.events or [])}
        )
        vocab = [PAD_TOKEN, BOS_TOKEN, EOS_TOKEN] + protos + labels + event_types + delays + methods + paths + headers + payloads + mutations
        return cls(vocab=vocab)

    def encode_token(self, token: str) -> int:
        return int(self.token_to_id[token])

    def _encode_condition(self, prefix: str, value: str) -> int:
        direct = f'{prefix}{value}'
        if direct in self.token_to_id:
            return int(self.token_to_id[direct])
        raise KeyError(f'unknown conditioned token: {direct}')

    def decode_token(self, token_id: int) -> str:
        return str(self.vocab[int(token_id)])

    def encode_sequence(self, protocol: str, label: str, events: Sequence[EventRecord | str], max_len: int) -> List[int]:
        seq = [self.bos_id, self._encode_condition(PROTO_PREFIX, protocol), self._encode_condition(LABEL_PREFIX, label)]
        for ev in list(events or []):
            event = ev if isinstance(ev, EventRecord) else EventRecord(event_type=str(ev))
            field_tokens = [
                f'{EVT_PREFIX}{str(event.event_type)}',
                f'{DELAY_PREFIX}{str(event.delay_bucket or "none")}',
                f'{METHOD_PREFIX}{str(event.method or "none").lower()}',
                f'{PATH_PREFIX}{str(event.path_bucket or "other")}',
                f'{HEADER_PREFIX}{str(event.header_profile or "none")}',
                f'{PAYLOAD_PREFIX}{str(event.payload_class or "none")}',
                f'{MUTATION_PREFIX}{str(event.mutation_signature or "none")}',
            ]
            for tok in field_tokens:
                if tok not in self.token_to_id:
                    raise KeyError(f'unknown field token: {tok}')
                seq.append(self.encode_token(tok))
            if len(seq) >= max_len - 1:
                break
        seq.append(self.eos_id)
        return seq[:max_len]

    def decode_event_token(self, token_id: int) -> str | None:
        tok = self.decode_token(token_id)
        if tok.startswith(EVT_PREFIX):
            return tok[len(EVT_PREFIX):]
        return None

    def allowed_event_token_ids(self, protocol: str) -> List[int]:
        key = str(protocol or '').strip().lower()
        ids = list(self._protocol_event_token_ids.get(key, []))
        if not ids:
            raise KeyError(f'no event vocabulary coverage for protocol={protocol}')
        return ids

    def allowed_field_token_ids(self, prefix: str) -> List[int]:
        mapping = {
            DELAY_PREFIX: self.delay_token_ids,
            METHOD_PREFIX: self.method_token_ids,
            PATH_PREFIX: self.path_token_ids,
            HEADER_PREFIX: self.header_token_ids,
            PAYLOAD_PREFIX: self.payload_token_ids,
            MUTATION_PREFIX: self.mutation_token_ids,
        }
        ids = list(mapping.get(prefix, []))
        if not ids:
            raise KeyError(f'no tokens for prefix={prefix}')
        return ids

    def token_id_for(self, prefix: str, value: str) -> int:
        tok = f'{prefix}{value}'
        if tok not in self.token_to_id:
            raise KeyError(f'unknown token: {tok}')
        return int(self.token_to_id[tok])


def _default_event_record(event_type: str) -> EventRecord:
    request_like = event_type in {'http_request', 'http2_headers', 'quic_request'}
    ws_like = event_type in {'ws_open', 'ws_frame'}
    return EventRecord(
        event_type=str(event_type),
        delay_bucket='6_20ms',
        method='get' if request_like else 'none',
        path_bucket='ws' if ws_like else ('api' if request_like else 'other'),
        header_profile='modern_browser' if request_like else 'none',
        payload_class='small' if request_like else 'none',
        mutation_signature='none',
    )


def _allowed_ids_for_event_field(codec: TokenCodec, prefix: str, protocol: str, event_type: str) -> List[int]:
    request_like = event_type in {'http_request', 'http2_headers', 'quic_request'}
    ws_like = event_type in {'ws_open', 'ws_frame'}
    if prefix == DELAY_PREFIX:
        return codec.allowed_field_token_ids(prefix)
    if prefix == METHOD_PREFIX:
        if request_like:
            return [i for i in codec.method_token_ids if codec.decode_token(i) != f'{METHOD_PREFIX}none']
        return [codec.token_id_for(METHOD_PREFIX, 'none')]
    if prefix == PATH_PREFIX:
        if request_like:
            return codec.path_token_ids
        if ws_like:
            return [codec.token_id_for(PATH_PREFIX, 'ws')]
        return [codec.token_id_for(PATH_PREFIX, 'other')]
    if prefix == HEADER_PREFIX:
        if request_like:
            return codec.header_token_ids
        return [codec.token_id_for(HEADER_PREFIX, 'none')]
    if prefix == PAYLOAD_PREFIX:
        if request_like:
            return codec.payload_token_ids
        return [codec.token_id_for(PAYLOAD_PREFIX, 'none')]
    if prefix == MUTATION_PREFIX:
        return codec.mutation_token_ids
    raise KeyError(f'unsupported prefix={prefix}')


class SequenceDataset(torch.utils.data.Dataset):
    # Dataset, degisken uzunluktaki token dizilerini pad ederek sabit max_len
    # tensore cevirir. Model next-token objective ile egitildigi icin
    # tek ihtiyacimiz input_ids tensorudur.
    def __init__(self, sessions: Sequence[SessionRecord], codec: TokenCodec, max_len: int) -> None:
        self.samples: List[List[int]] = []
        for session in list(sessions or []):
            try:
                encoded = codec.encode_sequence(session.protocol, session.label, session.events, int(max_len))
            except KeyError as exc:
                raise ValueError(f'session {session.session_id} is incompatible with codec: {exc}') from exc
            self.samples.append(encoded)
        self.max_len = int(max_len)
        self.pad_id = int(codec.pad_id)

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        seq = list(self.samples[int(idx)])
        if len(seq) < self.max_len:
            seq.extend([self.pad_id] * (self.max_len - len(seq)))
        else:
            seq = seq[: self.max_len]
        return {'input_ids': torch.tensor(seq, dtype=torch.long)}


class ResidualMambaBlock(nn.Module):
    def __init__(self, d_model: int, d_state: int, d_conv: int, expand: int) -> None:
        super().__init__()
        self.norm = nn.LayerNorm(d_model)
        self.mixer = Mamba(d_model=d_model, d_state=d_state, d_conv=d_conv, expand=expand)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.mixer(self.norm(x))


class MambaNextTokenModel(nn.Module):
    def __init__(self, vocab_size: int, hidden_size: int = 512, num_layers: int = 12, d_state: int = 16, d_conv: int = 4, expand: int = 2) -> None:
        super().__init__()
        self.embed = nn.Embedding(vocab_size, hidden_size)
        self.layers = nn.ModuleList([
            ResidualMambaBlock(d_model=hidden_size, d_state=d_state, d_conv=d_conv, expand=expand)
            for _ in range(int(num_layers))
        ])
        self.norm_f = nn.LayerNorm(hidden_size)
        self.head = nn.Linear(hidden_size, vocab_size, bias=False)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        x = self.embed(input_ids)
        for layer in self.layers:
            x = layer(x)
        x = self.norm_f(x)
        return self.head(x)


def build_model_from_config(vocab_size: int, config: Dict[str, Any]) -> MambaNextTokenModel:
    model_cfg = dict((config or {}).get('model', {}) or {})
    return MambaNextTokenModel(
        vocab_size=int(vocab_size),
        hidden_size=int(model_cfg.get('hidden_size', 512) or 512),
        num_layers=int(model_cfg.get('num_layers', 12) or 12),
        d_state=int(model_cfg.get('d_state', 16) or 16),
        d_conv=int(model_cfg.get('d_conv', 4) or 4),
        expand=int(model_cfg.get('expand', 2) or 2),
    )


def training_device(raw: str) -> torch.device:
    req = str(raw or 'cpu').strip().lower()
    if req in {'cuda', 'gpu'}:
        if not torch.cuda.is_available():
            raise RuntimeError('cuda/gpu requested but not available')
        return torch.device('cuda')
    return torch.device('cpu')


def seed_everything(seed: int) -> None:
    random.seed(int(seed))
    torch.manual_seed(int(seed))
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(int(seed))


@torch.no_grad()
def evaluate_model(model: MambaNextTokenModel, loader: torch.utils.data.DataLoader, *, pad_id: int, device: torch.device) -> Dict[str, float]:
    model.eval()
    total_loss = 0.0
    total_tokens = 0
    total_hit = 0
    total_pred = 0
    ce = nn.CrossEntropyLoss(ignore_index=int(pad_id), reduction='sum')
    for batch in loader:
        ids = batch['input_ids'].to(device)
        logits = model(ids)
        target = ids[:, 1:].contiguous()
        pred = logits[:, :-1, :].contiguous()
        loss = ce(pred.view(-1, pred.size(-1)), target.view(-1))
        total_loss += float(loss.item())
        mask = target.ne(int(pad_id))
        hit = pred.argmax(dim=-1).eq(target) & mask
        total_hit += int(hit.sum().item())
        total_pred += int(mask.sum().item())
        total_tokens += int(mask.sum().item())
    avg_nll = total_loss / float(max(1, total_tokens))
    ppl = float(math.exp(min(20.0, avg_nll)))
    acc = float(total_hit) / float(max(1, total_pred))
    return {
        'next_event_top1_accuracy': float(acc),
        'transition_perplexity': float(ppl),
        'transitions_eval': int(total_pred),
    }


def run_epoch(*, model: nn.Module, loader: torch.utils.data.DataLoader, optimizer: torch.optim.Optimizer, device: torch.device, pad_id: int, epoch: int, log_interval: int) -> Dict[str, float]:
    # Bu egitim dongusu bilincli olarak sade tutuldu.
    # Mixed precision, grad accumulation veya checkpointing eklemedik;
    # notebook'un okunabilirligini koruyup davranisi acik tutuyoruz.
    model.train()
    ce = nn.CrossEntropyLoss(ignore_index=int(pad_id), reduction='sum')
    total_loss = 0.0
    total_tokens = 0
    for step, batch in enumerate(loader, start=1):
        ids = batch['input_ids'].to(device)
        logits = model(ids)
        target = ids[:, 1:].contiguous()
        pred = logits[:, :-1, :].contiguous()
        loss = ce(pred.view(-1, pred.size(-1)), target.view(-1))
        token_count = int(target.ne(int(pad_id)).sum().item())
        norm_loss = loss / float(max(1, token_count))
        optimizer.zero_grad(set_to_none=True)
        norm_loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        total_loss += float(loss.item())
        total_tokens += token_count
        if int(log_interval or 0) > 0 and (step % int(log_interval)) == 0:
            step_nll = float(total_loss / float(max(1, total_tokens)))
            print(json.dumps({'epoch': int(epoch), 'step': int(step), 'steps_total': int(len(loader)), 'train_nll_running': float(step_nll), 'tokens_seen': int(total_tokens)}, sort_keys=True), flush=True)
    return {'nll': float(total_loss / float(max(1, total_tokens)))}


def save_checkpoint(path: str, *, model: MambaNextTokenModel, codec: TokenCodec, config: Dict[str, Any], dataset_meta: Dict[str, Any], metrics: Dict[str, Any], optimizer: Optional[torch.optim.Optimizer] = None, train_state: Optional[Dict[str, Any]] = None) -> None:
    # Resume training icin sadece model agirliklari yetmez.
    # Optimizer state'i ve tamamlanan epoch sayisini da kaydediyoruz.
    payload = {
        'format': 'mamba2_torch_v1',
        'created_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'model_name': str((config or {}).get('model', {}).get('name', 'mamba2-small')),
        'model_contract': 'multi_field_transition_lm_v2',
        'runtime_materialization': 'token_conditioned_v2',
        'config': dict(config or {}),
        'vocab': list(codec.vocab),
        'dataset': dict(dataset_meta or {}),
        'metrics': dict(metrics or {}),
        'state_dict': model.state_dict(),
        'optimizer_state_dict': (optimizer.state_dict() if optimizer is not None else None),
        'train_state': dict(train_state or {}),
    }
    torch.save(payload, str(path))


def load_checkpoint(path: str, *, map_location: str | torch.device = 'cpu') -> Dict[str, Any]:
    ck = torch.load(str(path), map_location=map_location)
    if not isinstance(ck, dict):
        raise RuntimeError('invalid checkpoint payload')
    if str(ck.get('format', '')) != 'mamba2_torch_v1':
        raise RuntimeError('checkpoint is not mamba2_torch_v1')
    return ck


def build_model_and_codec_from_checkpoint(checkpoint_path: str, *, device: str = 'cpu') -> Tuple[MambaNextTokenModel, TokenCodec, Dict[str, Any]]:
    map_loc = 'cpu' if str(device).lower() == 'cpu' else str(device)
    ck = load_checkpoint(checkpoint_path, map_location=map_loc)
    codec = TokenCodec(vocab=list(ck['vocab']))
    model = build_model_from_config(vocab_size=len(codec.vocab), config=dict(ck.get('config', {}) or {}))
    model.load_state_dict(dict(ck.get('state_dict', {}) or {}), strict=True)
    model.to(torch.device(device))
    model.eval()
    return model, codec, ck


@torch.no_grad()
def sample_event_types(model: MambaNextTokenModel, codec: TokenCodec, *, protocol: str, label: str, max_events: int, seed: int, device: str = 'cpu', temperature: float = 0.8, top_k: int = 20) -> List[EventRecord]:
    gen = torch.Generator(device='cpu')
    gen.manual_seed(int(seed))
    ids = codec.encode_sequence(protocol=protocol, label=label, events=[], max_len=3)
    out: List[EventRecord] = []
    model.eval()
    field_order = [EVT_PREFIX, DELAY_PREFIX, METHOD_PREFIX, PATH_PREFIX, HEADER_PREFIX, PAYLOAD_PREFIX, MUTATION_PREFIX]

    def _sample_from_allowed(allowed_ids: List[int]) -> int:
        x = torch.tensor([ids], dtype=torch.long, device=torch.device(device))
        logits = model(x)[:, -1, :].squeeze(0)
        mask = torch.full_like(logits, float('-inf'))
        mask[allowed_ids] = 0.0
        masked_logits = logits + mask
        temp = max(1e-4, float(temperature))
        masked_logits = masked_logits / temp
        if int(top_k) > 0 and int(top_k) < int(len(allowed_ids)):
            vals, idxs = torch.topk(masked_logits, k=int(top_k))
            probs = torch.softmax(vals, dim=-1)
            pick_local = int(torch.multinomial(probs, num_samples=1, generator=gen).item())
            return int(idxs[pick_local].item())
        probs = torch.softmax(masked_logits, dim=-1)
        return int(torch.multinomial(probs, num_samples=1, generator=gen).item())

    for _ in range(max(1, int(max_events))):
        next_id = _sample_from_allowed(list(codec.allowed_event_token_ids(protocol)) + [int(codec.eos_id)])
        if next_id == int(codec.eos_id):
            break
        ids.append(next_id)
        event_type = codec.decode_event_token(next_id)
        if not event_type:
            break
        event = _default_event_record(event_type)
        for prefix in field_order[1:]:
            field_id = _sample_from_allowed(_allowed_ids_for_event_field(codec, prefix, protocol, event_type))
            ids.append(field_id)
            token = codec.decode_token(field_id)
            value = token.split(':', 1)[1] if ':' in token else ''
            if prefix == DELAY_PREFIX:
                event = EventRecord(event_type=event.event_type, delay_bucket=value or 'none', method=event.method, path_bucket=event.path_bucket, header_profile=event.header_profile, payload_class=event.payload_class, mutation_signature=event.mutation_signature)
            elif prefix == METHOD_PREFIX:
                event = EventRecord(event_type=event.event_type, delay_bucket=event.delay_bucket, method=value or 'none', path_bucket=event.path_bucket, header_profile=event.header_profile, payload_class=event.payload_class, mutation_signature=event.mutation_signature)
            elif prefix == PATH_PREFIX:
                event = EventRecord(event_type=event.event_type, delay_bucket=event.delay_bucket, method=event.method, path_bucket=value or 'other', header_profile=event.header_profile, payload_class=event.payload_class, mutation_signature=event.mutation_signature)
            elif prefix == HEADER_PREFIX:
                event = EventRecord(event_type=event.event_type, delay_bucket=event.delay_bucket, method=event.method, path_bucket=event.path_bucket, header_profile=value or 'none', payload_class=event.payload_class, mutation_signature=event.mutation_signature)
            elif prefix == PAYLOAD_PREFIX:
                event = EventRecord(event_type=event.event_type, delay_bucket=event.delay_bucket, method=event.method, path_bucket=event.path_bucket, header_profile=event.header_profile, payload_class=value or 'none', mutation_signature=event.mutation_signature)
            elif prefix == MUTATION_PREFIX:
                event = EventRecord(event_type=event.event_type, delay_bucket=event.delay_bucket, method=event.method, path_bucket=event.path_bucket, header_profile=event.header_profile, payload_class=event.payload_class, mutation_signature=value or 'none')
        out.append(event)
    return out


def materialize_session_events(event_types: Sequence[EventRecord], *, protocol: str, label: str, session_len: int, seed: int) -> List[Dict[str, Any]]:
    rng = random.Random(int(seed))
    events: List[Dict[str, Any]] = []
    allowed = PROTOCOL_EVENT_TYPES.get(str(protocol), set())
    if not allowed:
        raise ValueError(f'unsupported protocol for materialization: {protocol}')
    seq = [ev for ev in list(event_types or []) if getattr(ev, 'event_type', '')]
    invalid = [ev.event_type for ev in seq if ev.event_type not in allowed]
    if invalid:
        raise ValueError(f'event types incompatible with protocol={protocol}: {invalid}')
    body = [ev for ev in seq if ev.event_type not in {'connect_open', 'close', 'reset'}]
    max_body_len = max(0, int(session_len) - 2)
    if len(body) > max_body_len:
        body = body[:max_body_len]
    seq = [_default_event_record('connect_open')] + body
    if len(seq) < int(session_len):
        seq.append(_default_event_record('close'))
    else:
        seq[-1] = _default_event_record('close')
    path_map = {'root': '/', 'api': '/api/v1/resource', 'ws': '/ws', 'static': '/static/app.js', 'auth': '/login', 'search': '/search', 'media': '/media/item', 'other': '/resource'}
    for i, ev in enumerate(seq):
        method = None
        path = None
        if ev.event_type in {'http_request', 'http2_headers', 'quic_request'}:
            method = str(ev.method or 'GET').upper()
            path = path_map.get(str(ev.path_bucket or 'other'), '/resource')
        elif ev.event_type in {'ws_open', 'ws_frame'}:
            path = '/ws'
        mutation_flags = []
        if str(ev.mutation_signature or 'none') != 'none':
            mutation_flags = [x for x in str(ev.mutation_signature).split('|') if x]
        if not mutation_flags and label in {'evasive', 'aggressive'} and rng.random() < 0.15:
            mutation_flags.append('header_shuffle')
        delay_ms_map = {'none': 0, '0_5ms': rng.randint(0, 5), '6_20ms': rng.randint(6, 20), '21_100ms': rng.randint(21, 100), '101_500ms': rng.randint(101, 500), '500ms_plus': rng.randint(501, 1000)}
        events.append({
            'step_index': int(i),
            'event_type': str(ev.event_type),
            'delay_ms': int(delay_ms_map.get(str(ev.delay_bucket or 'none'), rng.randint(1, 80))),
            'method': method,
            'path': path,
            'header_profile': None if str(ev.header_profile or 'none') == 'none' else str(ev.header_profile),
            'payload_class': None if str(ev.payload_class or 'none') == 'none' else str(ev.payload_class),
            'mutation_flags': mutation_flags,
            'expect_response_class': '2xx',
        })
    return events



def train_from_csv_dirs(*, train_csv_dir: str, val_csv_dir: str, out_dir: str, config: Dict[str, Any], device: str = 'cpu', csv_chunksize: int = 50000, max_train_rows_per_file: int = 0, max_val_rows_per_file: int = 0, max_train_sessions: int = 0, max_val_sessions: int = 0, num_workers: int = 0, batch_size_override: int = 0, epochs_override: int = 0, log_interval: int = 200) -> Dict[str, Any]:
    # Bu helper notebook icindeki ana egitim giris noktasi.
    # Ham CSV klasorlerinden session cikarir, vocab'i train setten kurar,
    # modeli egitir ve tek bir checkpoint + summary artefact uretir.
    train_sources = collect_csv_sources(csv_dir=str(train_csv_dir or '').strip(), csv_glob='*.csv', csv_files=[])
    val_sources = collect_csv_sources(csv_dir=str(val_csv_dir or '').strip(), csv_glob='*.csv', csv_files=[])
    if not train_sources:
        raise RuntimeError('No train CSV source found.')
    if not val_sources:
        raise RuntimeError('No val CSV source found.')

    train_sessions, train_rows_seen, train_files_seen = load_sessions_from_csv_sources(train_sources, max_sessions=int(max_train_sessions or 0), max_rows_per_file=int(max_train_rows_per_file or 0), csv_chunksize=int(csv_chunksize or 50000))
    val_sessions, val_rows_seen, val_files_seen = load_sessions_from_csv_sources(val_sources, max_sessions=int(max_val_sessions or 0), max_rows_per_file=int(max_val_rows_per_file or 0), csv_chunksize=int(csv_chunksize or 50000))
    if not train_sessions:
        raise RuntimeError('No train sessions extracted from CSV sources.')
    if not val_sessions:
        raise RuntimeError('No val sessions extracted from CSV sources.')

    train_label_set = {str(s.label or 'benign') for s in train_sessions}
    val_label_set = {str(s.label or 'benign') for s in val_sessions}
    missing_val_labels = sorted(val_label_set - train_label_set)
    allow_partial_coverage = any(int(x or 0) > 0 for x in (max_train_rows_per_file, max_val_rows_per_file, max_train_sessions, max_val_sessions))
    if missing_val_labels:
        msg = f'Validation labels train vocab disinda kaliyor: {missing_val_labels}. Spliti veya train dosyalarini guncelleyin.'
        if allow_partial_coverage:
            print(f'WARNING: {msg}', flush=True)
        else:
            raise RuntimeError(msg)
    train_protocol_set = {str(s.protocol or 'http1') for s in train_sessions}
    val_protocol_set = {str(s.protocol or 'http1') for s in val_sessions}
    missing_val_protocols = sorted(val_protocol_set - train_protocol_set)
    if missing_val_protocols:
        msg = f'Validation protocol coverage train setinde yok: {missing_val_protocols}. Spliti veya train dosyalarini guncelleyin.'
        if allow_partial_coverage:
            print(f'WARNING: {msg}', flush=True)
        else:
            raise RuntimeError(msg)

    codec = TokenCodec.build(train_sessions)
    max_len = int((config.get('model', {}) or {}).get('max_sequence_length', 128) or 128)
    train_ds = SequenceDataset(train_sessions, codec, max_len=max_len)
    val_ds = SequenceDataset(val_sessions, codec, max_len=max_len)

    train_cfg = dict(config.get('training', {}) or {})
    seed = int(train_cfg.get('seed', 1337) or 1337)
    seed_everything(seed)
    torch_device = training_device(device)
    batch_size = int(batch_size_override or 0) if int(batch_size_override or 0) > 0 else int(train_cfg.get('batch_size', 64) or 64)
    epochs = int(epochs_override or 0) if int(epochs_override or 0) > 0 else int(train_cfg.get('epochs', 10) or 10)

    train_loader = torch.utils.data.DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=max(0, int(num_workers)), pin_memory=bool(torch_device.type == 'cuda'), drop_last=False)
    val_loader = torch.utils.data.DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=max(0, int(num_workers)), pin_memory=bool(torch_device.type == 'cuda'), drop_last=False)

    model = build_model_from_config(vocab_size=len(codec.vocab), config=config).to(torch_device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(train_cfg.get('learning_rate', 3e-4) or 3e-4), weight_decay=float(train_cfg.get('weight_decay', 0.01) or 0.01))

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    history_path = out_path / 'train_metrics.jsonl'
    best_val_ppl = float('inf')
    best_metrics: Dict[str, Any] = {}
    best_state_dict: Optional[Dict[str, Any]] = None
    best_optimizer_state: Optional[Dict[str, Any]] = None

    run_meta = {
        'status': 'starting',
        'device': str(torch_device),
        'seed': int(seed),
        'batch_size': int(batch_size),
        'epochs': int(epochs),
        'steps_per_epoch_train': int(len(train_loader)),
        'steps_per_epoch_val': int(len(val_loader)),
        'rows_train': int(train_rows_seen),
        'rows_val': int(val_rows_seen),
        'sessions_train': int(len(train_sessions)),
        'sessions_val': int(len(val_sessions)),
        'train_csv_files': [str(p) for _lbl, p in train_sources],
        'val_csv_files': [str(p) for _lbl, p in val_sources],
    }
    print(json.dumps(run_meta, sort_keys=True), flush=True)

    with history_path.open('w', encoding='utf-8') as history_f:
        for epoch in range(1, epochs + 1):
            train_metrics = run_epoch(model=model, loader=train_loader, optimizer=optimizer, device=torch_device, pad_id=codec.pad_id, epoch=int(epoch), log_interval=int(log_interval or 0))
            val_metrics = evaluate_model(model, val_loader, pad_id=codec.pad_id, device=torch_device)
            epoch_metrics = {'epoch': float(epoch), 'train_nll': float(train_metrics['nll']), 'val_acc': float(val_metrics['next_event_top1_accuracy']), 'val_ppl': float(val_metrics['transition_perplexity'])}
            history_f.write(json.dumps(epoch_metrics, sort_keys=True) + '\n')
            history_f.flush()
            print(json.dumps(epoch_metrics, sort_keys=True), flush=True)
            if float(val_metrics['transition_perplexity']) < best_val_ppl:
                best_val_ppl = float(val_metrics['transition_perplexity'])
                best_metrics = {
                    'best_epoch': int(epoch),
                    'best_val_acc': float(val_metrics['next_event_top1_accuracy']),
                    'best_val_ppl': float(val_metrics['transition_perplexity']),
                    'transitions_eval': int(val_metrics['transitions_eval']),
                }
                best_state_dict = copy.deepcopy(model.state_dict())
                best_optimizer_state = copy.deepcopy(optimizer.state_dict())

    if best_state_dict is None:
        best_state_dict = copy.deepcopy(model.state_dict())
        best_optimizer_state = copy.deepcopy(optimizer.state_dict())
        best_metrics = {
            'best_epoch': int(epochs),
            'best_val_acc': float(val_metrics['next_event_top1_accuracy']),
            'best_val_ppl': float(val_metrics['transition_perplexity']),
            'transitions_eval': int(val_metrics['transitions_eval']),
        }
    model.load_state_dict(best_state_dict, strict=True)
    if best_optimizer_state is not None:
        optimizer.load_state_dict(best_optimizer_state)

    ckpt_name = f"mamba2_v1_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.ckpt.pt"
    ckpt_path = out_path / ckpt_name
    save_checkpoint(str(ckpt_path), model=model, codec=codec, config=config, dataset_meta={
        'rows_train': int(train_rows_seen),
        'rows_val': int(val_rows_seen),
        'sessions_train': int(len(train_sessions)),
        'sessions_val': int(len(val_sessions)),
        'train_files_seen': int(train_files_seen),
        'val_files_seen': int(val_files_seen),
        'train_csv_files': [str(p) for _lbl, p in train_sources],
        'val_csv_files': [str(p) for _lbl, p in val_sources],
    }, metrics=best_metrics, optimizer=optimizer, train_state={'last_epoch': int(epochs), 'completed_epochs': int(epochs)})
    summary = {
        'status': 'ok',
        'config': config,
        'device': str(torch_device),
        'model_contract': 'multi_field_transition_lm_v2',
        'runtime_materialization': 'token_conditioned_v2',
        'rows_train': int(train_rows_seen),
        'rows_val': int(val_rows_seen),
        'sessions_train': int(len(train_sessions)),
        'sessions_val': int(len(val_sessions)),
        'checkpoint_path': str(ckpt_path),
        'checkpoint_sha1': hashlib.sha1(ckpt_path.read_bytes()).hexdigest(),
        'best_metrics': best_metrics,
        'metrics_history_path': str(history_path),
        'train_csv_files': [str(p) for _lbl, p in train_sources],
        'val_csv_files': [str(p) for _lbl, p in val_sources],
    }
    (out_path / 'train_summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def eval_checkpoint_on_csv_dir(*, checkpoint_path: str, eval_csv_dir: str, device: str = 'cpu', batch_size: int = 64, num_workers: int = 0, csv_chunksize: int = 50000, max_eval_rows_per_file: int = 0, max_eval_sessions: int = 0) -> Dict[str, Any]:
    ckpt = Path(checkpoint_path)
    if not ckpt.exists():
        result = {'checkpoint_exists': False, 'checkpoint': str(ckpt), 'status': 'missing_checkpoint'}
        print(json.dumps(result, indent=2, sort_keys=True))
        return result
    eval_sources = collect_csv_sources(csv_dir=str(eval_csv_dir or '').strip(), csv_glob='*.csv', csv_files=[])
    if not eval_sources:
        raise RuntimeError('No eval CSV source found.')
    torch_device = training_device(device)
    model, codec, loaded = build_model_and_codec_from_checkpoint(str(ckpt), device=str(torch_device))
    sessions, rows_seen, files_seen = load_sessions_from_csv_sources(eval_sources, max_sessions=int(max_eval_sessions or 0), max_rows_per_file=int(max_eval_rows_per_file or 0), csv_chunksize=int(csv_chunksize or 50000))
    eval_labels = sorted({str(s.label or 'benign') for s in sessions})
    known_labels = {tok[len(LABEL_PREFIX):] for tok in codec.vocab if tok.startswith(LABEL_PREFIX)}
    missing_eval_labels = sorted(set(eval_labels) - known_labels)
    if missing_eval_labels:
        raise RuntimeError(f'Eval labels checkpoint vocab disinda kaliyor: {missing_eval_labels}. Train splitini veya checkpointi guncelleyin.')
    eval_protocols = sorted({str(s.protocol or 'http1') for s in sessions})
    known_protocols = {tok[len(PROTO_PREFIX):] for tok in codec.vocab if tok.startswith(PROTO_PREFIX)}
    missing_eval_protocols = sorted(set(eval_protocols) - known_protocols)
    if missing_eval_protocols:
        raise RuntimeError(f'Eval protocol coverage checkpoint vocab disinda kaliyor: {missing_eval_protocols}. Train splitini veya checkpointi guncelleyin.')
    max_len = int((loaded.get('config', {}) or {}).get('model', {}).get('max_sequence_length', 128) or 128)
    ds = SequenceDataset(sessions, codec, max_len=max_len)
    loader = torch.utils.data.DataLoader(ds, batch_size=max(1, int(batch_size)), shuffle=False, num_workers=max(0, int(num_workers)), pin_memory=bool(torch_device.type == 'cuda'), drop_last=False)
    metrics = evaluate_model(model, loader, pad_id=codec.pad_id, device=torch_device)
    result = {
        'checkpoint_exists': True,
        'checkpoint': str(ckpt),
        'status': 'ok',
        'model_contract': str(loaded.get('model_contract', 'multi_field_transition_lm_v2')),
        'runtime_materialization': str(loaded.get('runtime_materialization', 'token_conditioned_v2')),
        'eval_csv_files': [str(p) for _lbl, p in eval_sources],
        'eval_rows_seen': int(rows_seen),
        'eval_files_seen': int(files_seen),
        'sessions_eval': int(len(sessions)),
        'transitions_eval': int(metrics['transitions_eval']),
        'next_event_top1_accuracy': float(round(metrics['next_event_top1_accuracy'], 6)),
        'transition_perplexity': float(round(metrics['transition_perplexity'], 6)),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def find_latest_checkpoint(out_dir: str) -> Optional[str]:
    ckpts = sorted(Path(out_dir).glob('*.ckpt.pt'))
    if not ckpts:
        return None
    return str(ckpts[-1])


def resume_training_from_checkpoint(*, checkpoint_path: str, train_csv_dir: str, val_csv_dir: str, out_dir: str, additional_epochs: int, device: str = 'cpu', csv_chunksize: int = 50000, max_train_rows_per_file: int = 0, max_val_rows_per_file: int = 0, max_train_sessions: int = 0, max_val_sessions: int = 0, num_workers: int = 0, batch_size_override: int = 0, log_interval: int = 200) -> Dict[str, Any]:
    # Resume akisinda vocab ve model sekli checkpoint'ten gelir.
    # Bu kritik nokta su: resume sirasinda vocab'i tekrar train verisinden kurmuyoruz.
    # Aksi halde token id'leri kayar ve eski agirliklar anlamsiz hale gelir.
    ckpt = Path(checkpoint_path)
    if not ckpt.exists():
        raise RuntimeError(f'Checkpoint bulunamadi: {checkpoint_path}')
    loaded = load_checkpoint(str(ckpt), map_location='cpu' if str(device).lower() == 'cpu' else str(device))
    config = dict(loaded.get('config', {}) or {})
    train_sources = collect_csv_sources(csv_dir=str(train_csv_dir or '').strip(), csv_glob='*.csv', csv_files=[])
    val_sources = collect_csv_sources(csv_dir=str(val_csv_dir or '').strip(), csv_glob='*.csv', csv_files=[])
    if not train_sources:
        raise RuntimeError('No train CSV source found.')
    if not val_sources:
        raise RuntimeError('No val CSV source found.')

    train_sessions, train_rows_seen, train_files_seen = load_sessions_from_csv_sources(train_sources, max_sessions=int(max_train_sessions or 0), max_rows_per_file=int(max_train_rows_per_file or 0), csv_chunksize=int(csv_chunksize or 50000))
    val_sessions, val_rows_seen, val_files_seen = load_sessions_from_csv_sources(val_sources, max_sessions=int(max_val_sessions or 0), max_rows_per_file=int(max_val_rows_per_file or 0), csv_chunksize=int(csv_chunksize or 50000))
    if not train_sessions:
        raise RuntimeError('No train sessions extracted from CSV sources.')
    if not val_sessions:
        raise RuntimeError('No val sessions extracted from CSV sources.')

    train_label_set = {str(s.label or 'benign') for s in train_sessions}
    val_label_set = {str(s.label or 'benign') for s in val_sessions}
    missing_val_labels = sorted(val_label_set - train_label_set)
    allow_partial_coverage = any(int(x or 0) > 0 for x in (max_train_rows_per_file, max_val_rows_per_file, max_train_sessions, max_val_sessions))
    if missing_val_labels:
        msg = f'Resume validation labels train vocab disinda kaliyor: {missing_val_labels}. Spliti veya train dosyalarini guncelleyin.'
        if allow_partial_coverage:
            print(f'WARNING: {msg}', flush=True)
        else:
            raise RuntimeError(msg)
    train_protocol_set = {str(s.protocol or 'http1') for s in train_sessions}
    val_protocol_set = {str(s.protocol or 'http1') for s in val_sessions}
    missing_val_protocols = sorted(val_protocol_set - train_protocol_set)
    if missing_val_protocols:
        msg = f'Resume validation protocol coverage train setinde yok: {missing_val_protocols}. Spliti veya train dosyalarini guncelleyin.'
        if allow_partial_coverage:
            print(f'WARNING: {msg}', flush=True)
        else:
            raise RuntimeError(msg)

    codec = TokenCodec(vocab=list(loaded['vocab']))
    max_len = int((config.get('model', {}) or {}).get('max_sequence_length', 128) or 128)
    train_ds = SequenceDataset(train_sessions, codec, max_len=max_len)
    val_ds = SequenceDataset(val_sessions, codec, max_len=max_len)

    train_cfg = dict(config.get('training', {}) or {})
    seed = int(train_cfg.get('seed', 1337) or 1337)
    seed_everything(seed)
    torch_device = training_device(device)
    batch_size = int(batch_size_override or 0) if int(batch_size_override or 0) > 0 else int(train_cfg.get('batch_size', 64) or 64)
    add_epochs = max(1, int(additional_epochs or 1))

    train_loader = torch.utils.data.DataLoader(train_ds, batch_size=batch_size, shuffle=True, num_workers=max(0, int(num_workers)), pin_memory=bool(torch_device.type == 'cuda'), drop_last=False)
    val_loader = torch.utils.data.DataLoader(val_ds, batch_size=batch_size, shuffle=False, num_workers=max(0, int(num_workers)), pin_memory=bool(torch_device.type == 'cuda'), drop_last=False)

    model = build_model_from_config(vocab_size=len(codec.vocab), config=config).to(torch_device)
    model.load_state_dict(dict(loaded.get('state_dict', {}) or {}), strict=True)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(train_cfg.get('learning_rate', 3e-4) or 3e-4), weight_decay=float(train_cfg.get('weight_decay', 0.01) or 0.01))
    if loaded.get('optimizer_state_dict'):
        optimizer.load_state_dict(dict(loaded.get('optimizer_state_dict', {}) or {}))

    previous_epochs = int((loaded.get('train_state', {}) or {}).get('completed_epochs', 0) or 0)
    history_path = Path(out_dir) / 'train_metrics_resume.jsonl'
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    best_val_ppl = float('inf')
    best_metrics: Dict[str, Any] = {}
    best_state_dict: Optional[Dict[str, Any]] = None
    best_optimizer_state: Optional[Dict[str, Any]] = None

    with history_path.open('w', encoding='utf-8') as history_f:
        for local_epoch in range(1, add_epochs + 1):
            global_epoch = previous_epochs + local_epoch
            train_metrics = run_epoch(model=model, loader=train_loader, optimizer=optimizer, device=torch_device, pad_id=codec.pad_id, epoch=int(global_epoch), log_interval=int(log_interval or 0))
            val_metrics = evaluate_model(model, val_loader, pad_id=codec.pad_id, device=torch_device)
            epoch_metrics = {'epoch': float(global_epoch), 'train_nll': float(train_metrics['nll']), 'val_acc': float(val_metrics['next_event_top1_accuracy']), 'val_ppl': float(val_metrics['transition_perplexity'])}
            history_f.write(json.dumps(epoch_metrics, sort_keys=True) + '\n')
            history_f.flush()
            print(json.dumps(epoch_metrics, sort_keys=True), flush=True)
            if float(val_metrics['transition_perplexity']) < best_val_ppl:
                best_val_ppl = float(val_metrics['transition_perplexity'])
                best_metrics = {
                    'best_epoch': int(global_epoch),
                    'best_val_acc': float(val_metrics['next_event_top1_accuracy']),
                    'best_val_ppl': float(val_metrics['transition_perplexity']),
                    'transitions_eval': int(val_metrics['transitions_eval']),
                }
                best_state_dict = copy.deepcopy(model.state_dict())
                best_optimizer_state = copy.deepcopy(optimizer.state_dict())

    if best_state_dict is None:
        best_state_dict = copy.deepcopy(model.state_dict())
        best_optimizer_state = copy.deepcopy(optimizer.state_dict())
        best_metrics = {
            'best_epoch': int(previous_epochs + add_epochs),
            'best_val_acc': float(val_metrics['next_event_top1_accuracy']),
            'best_val_ppl': float(val_metrics['transition_perplexity']),
            'transitions_eval': int(val_metrics['transitions_eval']),
        }
    model.load_state_dict(best_state_dict, strict=True)
    if best_optimizer_state is not None:
        optimizer.load_state_dict(best_optimizer_state)

    resumed_epochs = previous_epochs + add_epochs
    ckpt_name = f"mamba2_resume_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.ckpt.pt"
    ckpt_path = Path(out_dir) / ckpt_name
    save_checkpoint(str(ckpt_path), model=model, codec=codec, config=config, dataset_meta={
        'rows_train': int(train_rows_seen),
        'rows_val': int(val_rows_seen),
        'sessions_train': int(len(train_sessions)),
        'sessions_val': int(len(val_sessions)),
        'train_files_seen': int(train_files_seen),
        'val_files_seen': int(val_files_seen),
        'train_csv_files': [str(p) for _lbl, p in train_sources],
        'val_csv_files': [str(p) for _lbl, p in val_sources],
        'resumed_from': str(ckpt),
    }, metrics=best_metrics, optimizer=optimizer, train_state={'last_epoch': int(resumed_epochs), 'completed_epochs': int(resumed_epochs), 'resumed_from': str(ckpt)})
    summary = {
        'status': 'ok',
        'mode': 'resume',
        'config': config,
        'device': str(torch_device),
        'checkpoint_path': str(ckpt_path),
        'checkpoint_sha1': hashlib.sha1(ckpt_path.read_bytes()).hexdigest(),
        'resumed_from': str(ckpt),
        'previous_completed_epochs': int(previous_epochs),
        'additional_epochs': int(add_epochs),
        'completed_epochs': int(resumed_epochs),
        'best_metrics': best_metrics,
        'metrics_history_path': str(history_path),
    }
    (Path(out_dir) / 'resume_summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def infer_plan_from_checkpoint(*, checkpoint_path: str, protocol: str, label: str, session_count: int, session_len: int, seed: int, device: str = 'cpu', temperature: float = 0.8, top_k: int = 20) -> TrafficPlan:
    # Inference iki asamalidir:
    # 1. Model token seviyesinde cok alanli EventRecord dizisi uretir.
    # 2. Materializer bu soyut alanlari runtime-benzeri event objelerine acar.
    model, codec, loaded = build_model_and_codec_from_checkpoint(checkpoint_path, device=device)
    session_plans: List[SessionPlan] = []
    for i in range(int(session_count)):
        evs = sample_event_types(model, codec, protocol=protocol, label=label, max_events=max(1, int(session_len) - 1), seed=int(seed) + i, device=device, temperature=float(temperature), top_k=int(top_k))
        materialized = materialize_session_events(evs, protocol=protocol, label=label, session_len=int(session_len), seed=int(seed) + i)
        session_plans.append(SessionPlan(
            session_id=f'infer-{protocol}-{label}-{i:04d}',
            protocol=str(protocol),
            label=str(label),
            events=[SessionEvent(**ev) for ev in materialized],
        ))
    plan = TrafficPlan(
        plan_id=f'plan-{seed}',
        model_name=str(loaded.get('model_name', 'mamba2-small')),
        checkpoint_id=hashlib.sha1(Path(checkpoint_path).read_bytes()).hexdigest()[:12],
        seed=int(seed),
        session_plans=session_plans,
    )
    vr = validate_plan(plan)
    if not vr.valid:
        raise RuntimeError(f'Inference plan validation failed: {vr.errors}')
    return plan




def _summary_empty(*, raw_root: Path, out_root: Path, input_format: str, source_files_total: int, pcap_source_total: int, csv_source_total: int, low_memory: bool) -> dict:
    return {
        'status': 'empty',
        'raw_dir': str(raw_root),
        'out_dir': str(out_root),
        'input_format': input_format,
        'low_memory': bool(low_memory),
        'source_files_total': source_files_total,
        'source_files_pcap': pcap_source_total,
        'source_files_csv': csv_source_total,
        'rows_total': 0,
    }


def build_dataset_pipeline(args: argparse.Namespace) -> tuple[int, dict]:
    raw_root = Path(args.raw_dir)
    out_root = Path(args.out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    input_format = str(args.input_format or 'auto').strip().lower()
    split_mode = str(args.split_mode or 'trace_session').strip().lower()
    files_by_label: Dict[str, List[Path]] = {'benign': [], 'evasive': [], 'aggressive': []}
    if input_format in {'auto', 'pcap'}:
        files_by_label = _collect_pcaps(raw_root)
    csv_sources: List[Tuple[str, Path]] = []
    if input_format in {'auto', 'csv'}:
        csv_sources = _collect_csv_sources(raw_root, str(args.csv_glob or '*.csv'), list(args.csv_file or []))

    if bool(args.low_memory):
        temp_root = Path(str(args.temp_dir or '').strip()) if str(args.temp_dir or '').strip() else (out_root / '.tmp_build')
        temp_root.mkdir(parents=True, exist_ok=True)
        spool_path = temp_root / 'events_spool.jsonl'
        source_files_total = 0
        empty_files: List[str] = []
        pcap_source_total = 0
        csv_source_total = 0
        rows_total = 0
        group_sizes: Dict[str, int] = {}
        with spool_path.open('w', encoding='utf-8') as spool_f:
            for label, files in files_by_label.items():
                for pcap in files:
                    source_files_total += 1
                    pcap_source_total += 1
                    source_events = 0
                    for row in _iter_event_dicts_for_source(kind='pcap', path=pcap, label=label, max_packets=int(args.max_packets_per_file or 0), max_rows=0, chunksize=0, progress_every=int(args.progress_every or 0)):
                        gid = _group_id_for_row(row, split_mode, rows_total)
                        row['__group_id'] = gid
                        spool_f.write(json.dumps(row, ensure_ascii=False) + '\n')
                        group_sizes[gid] = int(group_sizes.get(gid, 0)) + 1
                        rows_total += 1
                        source_events += 1
                    if source_events == 0:
                        empty_files.append(str(pcap))
                        if bool(args.fail_on_empty):
                            return 3, {}
            for label_hint, csv_path in csv_sources:
                source_files_total += 1
                csv_source_total += 1
                source_events = 0
                for row in _iter_event_dicts_for_source(kind='csv', path=csv_path, label=str(label_hint or '').strip().lower(), max_packets=0, max_rows=int(args.max_rows_per_file or 0), chunksize=int(args.csv_chunksize or 200000), progress_every=int(args.progress_every or 0)):
                    gid = _group_id_for_row(row, split_mode, rows_total)
                    row['__group_id'] = gid
                    spool_f.write(json.dumps(row, ensure_ascii=False) + '\n')
                    group_sizes[gid] = int(group_sizes.get(gid, 0)) + 1
                    rows_total += 1
                    source_events += 1
                if source_events == 0:
                    empty_files.append(str(csv_path))
                    if bool(args.fail_on_empty):
                        return 3, {}
        if rows_total == 0:
            summary = _summary_empty(raw_root=raw_root, out_root=out_root, input_format=input_format, source_files_total=source_files_total, pcap_source_total=pcap_source_total, csv_source_total=csv_source_total, low_memory=True)
            (out_root / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 2, summary
        assign = assign_groups_by_size(group_sizes, seed=int(args.seed), train_ratio=float(args.train_ratio), val_ratio=float(args.val_ratio))
        split_to_jsonl = {name: str(out_root / f'{name}.jsonl') for name in ('train', 'val', 'test')}
        row_counts = {'train': 0, 'val': 0, 'test': 0}
        split_hashes = {name: {'session_id': set(), 'trace_id': set()} for name in ('train', 'val', 'test')}
        with open(split_to_jsonl['train'], 'w', encoding='utf-8') as f_train, open(split_to_jsonl['val'], 'w', encoding='utf-8') as f_val, open(split_to_jsonl['test'], 'w', encoding='utf-8') as f_test:
            writers = {'train': f_train, 'val': f_val, 'test': f_test}
            with spool_path.open('r', encoding='utf-8') as f_spool:
                for line in f_spool:
                    raw = str(line or '').strip()
                    if not raw:
                        continue
                    row = json.loads(raw)
                    gid = str(row.pop('__group_id', '') or '')
                    split_name = str(assign.get(gid, 'test'))
                    if split_name not in writers:
                        split_name = 'test'
                    writers[split_name].write(json.dumps(row, ensure_ascii=False) + '\n')
                    row_counts[split_name] += 1
                    for key in ('session_id', 'trace_id'):
                        val = str(row.get(key, '') or '').strip()
                        if val:
                            split_hashes[split_name][key].add(_hash64(val))
        artifacts = {
            'train_jsonl': split_to_jsonl['train'],
            'val_jsonl': split_to_jsonl['val'],
            'test_jsonl': split_to_jsonl['test'],
            'train_parquet': export_jsonl_to_parquet(split_to_jsonl['train'], str(out_root / 'train.parquet'), chunk_rows=int(args.parquet_chunk_rows or 50000)),
            'val_parquet': export_jsonl_to_parquet(split_to_jsonl['val'], str(out_root / 'val.parquet'), chunk_rows=int(args.parquet_chunk_rows or 50000)),
            'test_parquet': export_jsonl_to_parquet(split_to_jsonl['test'], str(out_root / 'test.parquet'), chunk_rows=int(args.parquet_chunk_rows or 50000)),
        }
        leakage = {
            'train_val_session_id_overlap': _overlap_count_hashes(split_hashes['train']['session_id'], split_hashes['val']['session_id']),
            'train_test_session_id_overlap': _overlap_count_hashes(split_hashes['train']['session_id'], split_hashes['test']['session_id']),
            'val_test_session_id_overlap': _overlap_count_hashes(split_hashes['val']['session_id'], split_hashes['test']['session_id']),
            'train_val_trace_id_overlap': _overlap_count_hashes(split_hashes['train']['trace_id'], split_hashes['val']['trace_id']),
            'train_test_trace_id_overlap': _overlap_count_hashes(split_hashes['train']['trace_id'], split_hashes['test']['trace_id']),
            'val_test_trace_id_overlap': _overlap_count_hashes(split_hashes['val']['trace_id'], split_hashes['test']['trace_id']),
        }
        if not bool(args.keep_temp):
            try:
                spool_path.unlink(missing_ok=True)
            except Exception:
                pass
        summary = {
            'status': 'ok',
            'raw_dir': str(raw_root),
            'out_dir': str(out_root),
            'seed': int(args.seed),
            'input_format': input_format,
            'split_mode': split_mode,
            'low_memory': True,
            'source_files_total': source_files_total,
            'source_files_pcap': pcap_source_total,
            'source_files_csv': csv_source_total,
            'source_files_empty': len(empty_files),
            'source_files_empty_list': empty_files,
            'rows_total': int(rows_total),
            'rows_train': int(row_counts['train']),
            'rows_val': int(row_counts['val']),
            'rows_test': int(row_counts['test']),
            'groups_total': int(len(group_sizes)),
            'leakage': leakage,
            'artifacts': artifacts,
        }
        (out_root / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0, summary

    all_rows: List[dict] = []
    source_files_total = 0
    empty_files: List[str] = []
    pcap_source_total = 0
    csv_source_total = 0
    for label, files in files_by_label.items():
        for pcap in files:
            source_files_total += 1
            pcap_source_total += 1
            events = pcap_to_normalized_events(str(pcap), protocol_profile=f'label={label}', max_packets=int(args.max_packets_per_file or 0), progress_every=int(args.progress_every or 0), progress_cb=None)
            if len(events) == 0:
                empty_files.append(str(pcap))
                if bool(args.fail_on_empty):
                    return 3, {}
            all_rows.extend(ev.to_dict() for ev in events)
    for label_hint, csv_path in csv_sources:
        source_files_total += 1
        csv_source_total += 1
        label_profile = str(label_hint or '').strip().lower()
        profile = f'label={label_profile}' if label_profile else ''
        rows = [
            ev.to_dict()
            for ev in iter_csv_normalized_events(
                str(csv_path),
                protocol_profile=profile,
                default_label=label_profile or 'benign',
                max_rows=int(args.max_rows_per_file or 0),
                chunksize=int(args.csv_chunksize or 200000),
                progress_every=int(args.progress_every or 0),
                progress_cb=None,
            )
        ]
        if len(rows) == 0:
            empty_files.append(str(csv_path))
            if bool(args.fail_on_empty):
                return 3, {}
        all_rows.extend(rows)
    if not all_rows:
        summary = _summary_empty(raw_root=raw_root, out_root=out_root, input_format=input_format, source_files_total=source_files_total, pcap_source_total=pcap_source_total, csv_source_total=csv_source_total, low_memory=False)
        (out_root / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 2, summary
    if split_mode == 'row':
        split = split_dataset(all_rows, seed=int(args.seed), train_ratio=float(args.train_ratio), val_ratio=float(args.val_ratio))
    else:
        pri = ['session_id'] if split_mode == 'session' else (['trace_id'] if split_mode == 'trace' else ['trace_id', 'session_id'])
        split = split_rows_group_aware(all_rows, seed=int(args.seed), train_ratio=float(args.train_ratio), val_ratio=float(args.val_ratio), group_priority_fields=pri)
    train_rows, val_rows, test_rows = split.train, split.val, split.test
    artifacts = {
        'train_jsonl': export_jsonl(train_rows, str(out_root / 'train.jsonl')),
        'val_jsonl': export_jsonl(val_rows, str(out_root / 'val.jsonl')),
        'test_jsonl': export_jsonl(test_rows, str(out_root / 'test.jsonl')),
        'train_parquet': export_parquet(train_rows, str(out_root / 'train.parquet')),
        'val_parquet': export_parquet(val_rows, str(out_root / 'val.parquet')),
        'test_parquet': export_parquet(test_rows, str(out_root / 'test.parquet')),
    }
    leakage = {
        'train_val_session_id_overlap': _overlap_count_rows(train_rows, val_rows, 'session_id'),
        'train_test_session_id_overlap': _overlap_count_rows(train_rows, test_rows, 'session_id'),
        'val_test_session_id_overlap': _overlap_count_rows(val_rows, test_rows, 'session_id'),
        'train_val_trace_id_overlap': _overlap_count_rows(train_rows, val_rows, 'trace_id'),
        'train_test_trace_id_overlap': _overlap_count_rows(train_rows, test_rows, 'trace_id'),
        'val_test_trace_id_overlap': _overlap_count_rows(val_rows, test_rows, 'trace_id'),
    }
    summary = {
        'status': 'ok',
        'raw_dir': str(raw_root),
        'out_dir': str(out_root),
        'seed': int(args.seed),
        'input_format': input_format,
        'split_mode': split_mode,
        'low_memory': False,
        'source_files_total': source_files_total,
        'source_files_pcap': pcap_source_total,
        'source_files_csv': csv_source_total,
        'source_files_empty': len(empty_files),
        'source_files_empty_list': empty_files,
        'rows_total': int(len(all_rows)),
        'rows_train': int(len(train_rows)),
        'rows_val': int(len(val_rows)),
        'rows_test': int(len(test_rows)),
        'leakage': leakage,
        'artifacts': artifacts,
    }
    (out_root / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0, summary



DEFAULT_PROFILES = {
    'gtx1650_4gb': {
        'model': {'name': 'mamba2-monolith-1650-4gb', 'max_sequence_length': 96, 'hidden_size': 256, 'num_layers': 6, 'd_state': 16, 'd_conv': 4, 'expand': 2},
        'training': {'epochs': 3, 'batch_size': 2, 'learning_rate': 3e-4, 'weight_decay': 0.01, 'seed': 1337},
    },
    'ultra_low_vram': {
        'model': {'name': 'mamba2-monolith-ultra-low-vram', 'max_sequence_length': 64, 'hidden_size': 192, 'num_layers': 4, 'd_state': 16, 'd_conv': 4, 'expand': 2},
        'training': {'epochs': 3, 'batch_size': 1, 'learning_rate': 3e-4, 'weight_decay': 0.01, 'seed': 1337},
    },
}


def _find_code_root() -> Path:
    cwd = Path.cwd().resolve()
    for candidate in [cwd, *cwd.parents]:
        if (candidate / 'training').exists() and (candidate / 'ddos_samurai').exists():
            return candidate
    raise RuntimeError('CODE_ROOT otomatik bulunamadi.')


def _load_runtime_config(profile: str, *, config_file: str = '', smoke: bool = False) -> Dict[str, Any]:
    if config_file:
        raw = Path(config_file).read_text(encoding='utf-8')
        config = json.loads(raw) if str(config_file).lower().endswith('.json') else yaml.safe_load(raw)
    else:
        if profile not in DEFAULT_PROFILES:
            raise RuntimeError(f'Unknown profile: {profile}')
        config = json.loads(json.dumps(DEFAULT_PROFILES[profile]))
    config['objective'] = {
        'type': 'autoregressive_multi_field_sequence',
        'fields': ['event_type', 'delay_bucket', 'method', 'path_bucket', 'header_profile', 'payload_class', 'mutation_signature'],
    }
    if smoke:
        config['model'].update({'name': f"{config['model']['name']}-smoke", 'max_sequence_length': 48, 'hidden_size': 64, 'num_layers': 2, 'd_state': 8, 'd_conv': 4, 'expand': 2})
        config['training'].update({'epochs': 1, 'batch_size': 1, 'learning_rate': 3e-4, 'weight_decay': 0.01, 'seed': 1337})
    return config


def _read_label_values(csv_path: Path) -> List[str]:
    for col in (' Label', 'Label', 'label'):
        try:
            df = pd.read_csv(csv_path, usecols=[col], low_memory=False)
            return sorted({str(x).strip() for x in df.iloc[:, 0].dropna().unique().tolist() if str(x).strip()})
        except Exception:
            continue
    return []


def _read_protocol_values(csv_path: Path, *, max_rows: int = 5000) -> List[str]:
    protocols: set[str] = set()
    for ev in iter_csv_normalized_events(str(csv_path), default_label='benign', max_rows=int(max_rows or 0), chunksize=2000):
        protocols.add(str(ev.protocol or 'http1'))
    return sorted(protocols)


def _file_profiles(files: Sequence[Path]) -> Dict[str, Dict[str, List[str]]]:
    profiles: Dict[str, Dict[str, List[str]]] = {}
    for csv_path in files:
        profiles[csv_path.name] = {
            'labels': sorted({_map_label(raw) for raw in _read_label_values(csv_path)}),
            'protocols': _read_protocol_values(csv_path),
        }
    return profiles


def _coverage_for(names: Sequence[str], profiles: Dict[str, Dict[str, List[str]]], field: str) -> set[str]:
    covered: set[str] = set()
    for name in names:
        covered.update(profiles.get(name, {}).get(field, []))
    return covered


def choose_auto_split(files: Sequence[Path], *, auto_test_keywords: Sequence[str] = ('ddos', 'portscan')) -> tuple[List[str], List[str], List[str], Dict[str, Dict[str, List[str]]]]:
    profiles = _file_profiles(files)
    names = sorted(profiles)
    test_files = sorted([name for name in names if any(key in name.lower() for key in auto_test_keywords)])
    remaining = [name for name in names if name not in test_files]
    if not remaining:
        raise RuntimeError('Auto split icin train/val adayi kalmadi.')
    candidates: List[tuple[tuple[int, int, int, int, str], str]] = []
    for name in remaining:
        train_files = [candidate for candidate in remaining if candidate != name]
        if not train_files:
            continue
        train_labels = _coverage_for(train_files, profiles, 'labels')
        target_labels = _coverage_for([name] + test_files, profiles, 'labels')
        train_protocols = _coverage_for(train_files, profiles, 'protocols')
        target_protocols = _coverage_for([name] + test_files, profiles, 'protocols')
        if not target_labels.issubset(train_labels):
            continue
        if not target_protocols.issubset(train_protocols):
            continue
        labels = set(profiles.get(name, {}).get('labels', []))
        score = (int('evasive' in labels), int('benign' in labels), -int('aggressive' in labels), -len(labels), name)
        candidates.append((score, name))
    if not candidates:
        raise RuntimeError('Auto split train coverage koruyarak val secemedi.')
    candidates.sort(reverse=True)
    val_files = [candidates[0][1]]
    train_files = [name for name in remaining if name not in val_files]
    return sorted(train_files), sorted(val_files), sorted(test_files), profiles


def materialize_split_dirs(*, data_root: str, work_root: str, csv_glob: str = '*.csv') -> Dict[str, Any]:
    root = Path(data_root)
    work = Path(work_root)
    csv_files = sorted(root.glob(csv_glob)) if root.exists() else []
    if not csv_files:
        raise RuntimeError(f'No CSV files found under {data_root} with glob={csv_glob}')
    train_files, val_files, test_files, profiles = choose_auto_split(csv_files)
    split_root = work / 'csv_split'
    for part in ('train', 'val', 'test'):
        part_dir = split_root / part
        part_dir.mkdir(parents=True, exist_ok=True)
        for old in part_dir.glob('*.csv'):
            old.unlink()
    available = {p.name: p for p in csv_files}
    for part, names in {'train': train_files, 'val': val_files, 'test': test_files}.items():
        for name in names:
            shutil.copy2(available[name], split_root / part / name)
    result = {
        'split_root': str(split_root),
        'train_files': train_files,
        'val_files': val_files,
        'test_files': test_files,
        'profiles': profiles,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def run_profile_pipeline(args: argparse.Namespace) -> int:
    code_root = Path(args.code_root).resolve() if args.code_root else _find_code_root()
    data_root = Path(args.data_root).resolve() if args.data_root else (code_root / 'data' / 'raw' / 'cicids2017')
    work_root = Path(args.work_root).resolve() if args.work_root else (code_root / 'monolith_runs' / 'mamba2_monolith')
    work_root.mkdir(parents=True, exist_ok=True)
    split_info = materialize_split_dirs(data_root=str(data_root), work_root=str(work_root), csv_glob=str(args.csv_glob or '*.csv'))
    config = _load_runtime_config(args.profile, config_file=str(args.config_file or ''), smoke=bool(args.smoke))
    device = str(args.device or ('cuda' if torch.cuda.is_available() else 'cpu'))
    csv_chunksize = 1000 if bool(args.smoke) else 10000
    train_limits = {
        'max_train_rows_per_file': 500 if bool(args.smoke) else 0,
        'max_val_rows_per_file': 300 if bool(args.smoke) else 0,
        'max_train_sessions': 64 if bool(args.smoke) else 0,
        'max_val_sessions': 32 if bool(args.smoke) else 0,
    }
    eval_limits = {'max_eval_rows_per_file': 300 if bool(args.smoke) else 0, 'max_eval_sessions': 32 if bool(args.smoke) else 0}
    out_dir = work_root / ('smoke_run' if bool(args.smoke) else 'run1')
    out_dir.mkdir(parents=True, exist_ok=True)
    train_summary = train_from_csv_dirs(train_csv_dir=str(Path(split_info['split_root']) / 'train'), val_csv_dir=str(Path(split_info['split_root']) / 'val'), out_dir=str(out_dir), config=config, device=device, csv_chunksize=csv_chunksize, batch_size_override=int(config['training']['batch_size']), epochs_override=int(config['training']['epochs']), log_interval=0 if bool(args.smoke) else 20, **train_limits)
    resume_summary = resume_training_from_checkpoint(checkpoint_path=str(find_latest_checkpoint(str(out_dir)) or train_summary['checkpoint_path']), train_csv_dir=str(Path(split_info['split_root']) / 'train'), val_csv_dir=str(Path(split_info['split_root']) / 'val'), out_dir=str(out_dir), additional_epochs=1 if bool(args.smoke) else 2, device=device, csv_chunksize=csv_chunksize, batch_size_override=int(config['training']['batch_size']), log_interval=0 if bool(args.smoke) else 20, max_train_rows_per_file=int(train_limits['max_train_rows_per_file']), max_val_rows_per_file=int(train_limits['max_val_rows_per_file']), max_train_sessions=int(train_limits['max_train_sessions']), max_val_sessions=int(train_limits['max_val_sessions']))
    checkpoint_path = str(resume_summary.get('checkpoint_path') or train_summary['checkpoint_path'])
    eval_result = eval_checkpoint_on_csv_dir(checkpoint_path=checkpoint_path, eval_csv_dir=str(Path(split_info['split_root']) / 'test'), device=device, batch_size=2 if bool(args.smoke) else 4, csv_chunksize=csv_chunksize, **eval_limits)
    plan = infer_plan_from_checkpoint(checkpoint_path=checkpoint_path, protocol='http1', label='benign', session_count=1 if bool(args.smoke) else 2, session_len=6, seed=1337, device=device, temperature=0.8, top_k=10)
    plan_path = out_dir / 'inference_plan.json'
    plan_path.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True), encoding='utf-8')
    result = {'train_summary': train_summary, 'resume_summary': resume_summary, 'eval_result': eval_result, 'plan_path': str(plan_path)}
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Single-file Mamba-2 monolith')
    sub = p.add_subparsers(dest='command', required=True)

    ds = sub.add_parser('build-dataset', help='Build dataset from CSV/PCAP sources')
    ds.add_argument('--raw-dir', type=str, default='data/raw')
    ds.add_argument('--out-dir', type=str, default='data/processed/v1')
    ds.add_argument('--seed', type=int, default=1337)
    ds.add_argument('--train-ratio', type=float, default=0.8)
    ds.add_argument('--val-ratio', type=float, default=0.1)
    ds.add_argument('--input-format', choices=['auto', 'pcap', 'csv'], default='auto')
    ds.add_argument('--csv-glob', type=str, default='*.csv')
    ds.add_argument('--csv-file', action='append', default=[])
    ds.add_argument('--max-rows-per-file', type=int, default=0)
    ds.add_argument('--csv-chunksize', type=int, default=200000)
    ds.add_argument('--max-packets-per-file', type=int, default=0)
    ds.add_argument('--progress-every', type=int, default=200000)
    ds.add_argument('--fail-on-empty', action='store_true')
    ds.add_argument('--split-mode', choices=['row', 'session', 'trace', 'trace_session'], default='trace_session')
    ds.add_argument('--low-memory', action='store_true')
    ds.add_argument('--temp-dir', type=str, default='')
    ds.add_argument('--keep-temp', action='store_true')
    ds.add_argument('--parquet-chunk-rows', type=int, default=50000)

    split = sub.add_parser('auto-split', help='Create train/val/test CSV directories')
    split.add_argument('--data-root', type=str, required=True)
    split.add_argument('--work-root', type=str, required=True)
    split.add_argument('--csv-glob', type=str, default='*.csv')

    train = sub.add_parser('train', help='Train from prepared train/val CSV dirs')
    train.add_argument('--train-csv-dir', type=str, required=True)
    train.add_argument('--val-csv-dir', type=str, required=True)
    train.add_argument('--out-dir', type=str, required=True)
    train.add_argument('--profile', type=str, default='gtx1650_4gb')
    train.add_argument('--config-file', type=str, default='')
    train.add_argument('--smoke', action='store_true')
    train.add_argument('--device', type=str, default='')
    train.add_argument('--csv-chunksize', type=int, default=50000)
    train.add_argument('--max-train-rows-per-file', type=int, default=0)
    train.add_argument('--max-val-rows-per-file', type=int, default=0)
    train.add_argument('--max-train-sessions', type=int, default=0)
    train.add_argument('--max-val-sessions', type=int, default=0)
    train.add_argument('--num-workers', type=int, default=0)
    train.add_argument('--batch-size-override', type=int, default=0)
    train.add_argument('--epochs-override', type=int, default=0)
    train.add_argument('--log-interval', type=int, default=200)

    resume = sub.add_parser('resume', help='Resume training from checkpoint')
    resume.add_argument('--checkpoint-path', type=str, required=True)
    resume.add_argument('--train-csv-dir', type=str, required=True)
    resume.add_argument('--val-csv-dir', type=str, required=True)
    resume.add_argument('--out-dir', type=str, required=True)
    resume.add_argument('--additional-epochs', type=int, required=True)
    resume.add_argument('--device', type=str, default='cpu')
    resume.add_argument('--csv-chunksize', type=int, default=50000)
    resume.add_argument('--max-train-rows-per-file', type=int, default=0)
    resume.add_argument('--max-val-rows-per-file', type=int, default=0)
    resume.add_argument('--max-train-sessions', type=int, default=0)
    resume.add_argument('--max-val-sessions', type=int, default=0)
    resume.add_argument('--num-workers', type=int, default=0)
    resume.add_argument('--batch-size-override', type=int, default=0)
    resume.add_argument('--log-interval', type=int, default=200)

    ev = sub.add_parser('eval', help='Evaluate checkpoint on CSV dir')
    ev.add_argument('--checkpoint-path', type=str, required=True)
    ev.add_argument('--eval-csv-dir', type=str, required=True)
    ev.add_argument('--device', type=str, default='cpu')
    ev.add_argument('--batch-size', type=int, default=64)
    ev.add_argument('--num-workers', type=int, default=0)
    ev.add_argument('--csv-chunksize', type=int, default=50000)
    ev.add_argument('--max-eval-rows-per-file', type=int, default=0)
    ev.add_argument('--max-eval-sessions', type=int, default=0)

    inf = sub.add_parser('infer-plan', help='Infer a traffic plan from a checkpoint')
    inf.add_argument('--checkpoint-path', type=str, required=True)
    inf.add_argument('--protocol', type=str, required=True)
    inf.add_argument('--label', type=str, required=True)
    inf.add_argument('--session-count', type=int, default=1)
    inf.add_argument('--session-len', type=int, default=6)
    inf.add_argument('--seed', type=int, default=1337)
    inf.add_argument('--device', type=str, default='cpu')
    inf.add_argument('--temperature', type=float, default=0.8)
    inf.add_argument('--top-k', type=int, default=20)
    inf.add_argument('--out', type=str, default='')

    pipe = sub.add_parser('run-profile', help='Notebook-like end-to-end pipeline')
    pipe.add_argument('--code-root', type=str, default='')
    pipe.add_argument('--data-root', type=str, default='')
    pipe.add_argument('--work-root', type=str, default='')
    pipe.add_argument('--csv-glob', type=str, default='*.csv')
    pipe.add_argument('--profile', type=str, default='gtx1650_4gb')
    pipe.add_argument('--config-file', type=str, default='')
    pipe.add_argument('--device', type=str, default='')
    pipe.add_argument('--smoke', action='store_true')
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_cli()
    args = parser.parse_args(list(argv) if argv is not None else None)
    cmd = str(args.command)
    if cmd == 'build-dataset':
        code, _ = build_dataset_pipeline(args)
        return int(code)
    if cmd == 'auto-split':
        materialize_split_dirs(data_root=str(args.data_root), work_root=str(args.work_root), csv_glob=str(args.csv_glob))
        return 0
    if cmd == 'train':
        config = _load_runtime_config(str(args.profile), config_file=str(args.config_file or ''), smoke=bool(args.smoke))
        device = str(args.device or ('cuda' if torch.cuda.is_available() else 'cpu'))
        train_from_csv_dirs(train_csv_dir=str(args.train_csv_dir), val_csv_dir=str(args.val_csv_dir), out_dir=str(args.out_dir), config=config, device=device, csv_chunksize=int(args.csv_chunksize), max_train_rows_per_file=int(args.max_train_rows_per_file), max_val_rows_per_file=int(args.max_val_rows_per_file), max_train_sessions=int(args.max_train_sessions), max_val_sessions=int(args.max_val_sessions), num_workers=int(args.num_workers), batch_size_override=int(args.batch_size_override), epochs_override=int(args.epochs_override), log_interval=int(args.log_interval))
        return 0
    if cmd == 'resume':
        resume_training_from_checkpoint(checkpoint_path=str(args.checkpoint_path), train_csv_dir=str(args.train_csv_dir), val_csv_dir=str(args.val_csv_dir), out_dir=str(args.out_dir), additional_epochs=int(args.additional_epochs), device=str(args.device), csv_chunksize=int(args.csv_chunksize), max_train_rows_per_file=int(args.max_train_rows_per_file), max_val_rows_per_file=int(args.max_val_rows_per_file), max_train_sessions=int(args.max_train_sessions), max_val_sessions=int(args.max_val_sessions), num_workers=int(args.num_workers), batch_size_override=int(args.batch_size_override), log_interval=int(args.log_interval))
        return 0
    if cmd == 'eval':
        eval_checkpoint_on_csv_dir(checkpoint_path=str(args.checkpoint_path), eval_csv_dir=str(args.eval_csv_dir), device=str(args.device), batch_size=int(args.batch_size), num_workers=int(args.num_workers), csv_chunksize=int(args.csv_chunksize), max_eval_rows_per_file=int(args.max_eval_rows_per_file), max_eval_sessions=int(args.max_eval_sessions))
        return 0
    if cmd == 'infer-plan':
        plan = infer_plan_from_checkpoint(checkpoint_path=str(args.checkpoint_path), protocol=str(args.protocol), label=str(args.label), session_count=int(args.session_count), session_len=int(args.session_len), seed=int(args.seed), device=str(args.device), temperature=float(args.temperature), top_k=int(args.top_k))
        payload = json.dumps(plan.to_dict(), indent=2, sort_keys=True)
        if str(args.out or '').strip():
            Path(str(args.out)).write_text(payload, encoding='utf-8')
        print(payload)
        return 0
    if cmd == 'run-profile':
        return int(run_profile_pipeline(args))
    raise RuntimeError(f'Unsupported command: {cmd}')


if __name__ == '__main__':
    raise SystemExit(main())
